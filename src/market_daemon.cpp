/*
 * ============================================================================
 * PROJECT: HEAB + SBM Financial Execution Stack v7.0 (PRODUCTION)
 * MODULE: market_daemon.cpp
 * CORRECTIONS IN V7.0:
 * - Atomic flag + sigaction for async-signal-safe shutdown
 * - posix_fallocate EINTR retry + ENOSPC handling
 * - mmap_ptr as class member (fixes compile error)
 * ============================================================================
 */

#define _GNU_SOURCE
#include <iostream>
#include <fstream>
#include <string>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <thread>
#include <chrono>
#include <pthread.h>
#ifdef __aarch64__
    // Apple Silicon / ARM64
    inline uint64_t rdtsc_serialized() {
        std::atomic_thread_fence(std::memory_order_seq_cst);
        uint64_t tsc;
        // Read virtual counter (CNTVCT_EL0)
        asm volatile("mrs %0, cntvct_el0" : "=r"(tsc));
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return tsc;
    }
#else
    // x86_64
    #include <immintrin.h>
    inline uint64_t rdtsc_serialized() {
        _mm_lfence();
        uint64_t tsc = __builtin_ia32_rdtsc();
        _mm_lfence();
        return tsc;
    }
#endif

class ApexDaemon {
public:
    ShmRingBuffer* ring_buffer;
    int shm_id;
    std::atomic<bool> running{true};
    std::atomic<uint64_t>* mmap_nonce;
    void* mmap_ptr;

    ApexDaemon() {
        bool is_existing_shm = false;
        shm_id = shmget(SHM_KEY, sizeof(ShmRingBuffer), IPC_CREAT | IPC_EXCL | 0666 | SHM_HUGETLB);

        if (shm_id < 0 && errno == EEXIST) {
            shm_id = shmget(SHM_KEY, 0, 0666 | SHM_HUGETLB);
            is_existing_shm = true;
        } else if (shm_id < 0) {
            shm_id = shmget(SHM_KEY, sizeof(ShmRingBuffer), IPC_CREAT | IPC_EXCL | 0666);
            if (shm_id < 0 && errno == EEXIST) {
                shm_id = shmget(SHM_KEY, 0, 0666);
                is_existing_shm = true;
            }
        }

        ring_buffer = (ShmRingBuffer*)shmat(shm_id, NULL, 0);
        madvise(ring_buffer, sizeof(ShmRingBuffer), MADV_HUGEPAGE | MADV_SEQUENTIAL);

        if (!is_existing_shm) {
            ring_buffer->head.store(0, std::memory_order_relaxed);
            ring_buffer->tail.store(0, std::memory_order_relaxed);
        }

        int fd = open("nonce.bin", O_RDWR | O_CREAT, 0666);
        bool is_new_file = (lseek(fd, 0, SEEK_END) == 0);
        if (is_new_file) safe_fallocate(fd, 0, sizeof(std::atomic<uint64_t>), "nonce.bin");

        mmap_ptr = mmap(NULL, sizeof(std::atomic<uint64_t>), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        madvise(mmap_ptr, sizeof(std::atomic<uint64_t>), MADV_HUGEPAGE);

        if (is_new_file) {
            mmap_nonce = new (mmap_ptr) std::atomic<uint64_t>(1);
        } else {
            mmap_nonce = reinterpret_cast<std::atomic<uint64_t>*>(mmap_ptr);
            uint64_t persisted = mmap_nonce->load(std::memory_order_acquire);
            if (persisted == 0 || persisted > 10000000ULL) {
                mmap_nonce->store(1, std::memory_order_release);
            }
        }
    }

    ~ApexDaemon() {
        munmap(mmap_ptr, sizeof(std::atomic<uint64_t>));
        shmdt(ring_buffer);
    }

    void checkpoint_nonce_async(uint64_t n) {
        mmap_nonce->store(n, std::memory_order_release);
        msync(mmap_ptr, sizeof(std::atomic<uint64_t>), MS_ASYNC);
    }

    void checkpoint_nonce_sync_shutdown(uint64_t n) {
        mmap_nonce->store(n, std::memory_order_release);
        msync(mmap_ptr, sizeof(std::atomic<uint64_t>), MS_SYNC);
    }

    inline bool push_tick(const NormalizedTick& tick) {
        uint32_t head = ring_buffer->head.load(std::memory_order_relaxed);
        uint32_t next = (head + 1) & (RING_SIZE - 1);
        if (next == ring_buffer->tail.load(std::memory_order_acquire)) return false;
        ring_buffer->ticks[head] = tick;
        ring_buffer->head.store(next, std::memory_order_release);
        return true;
    }

    inline int pop_batch(NormalizedTick* out, int max_count) {
        uint32_t tail = ring_buffer->tail.load(std::memory_order_relaxed);
        uint32_t head = ring_buffer->head.load(std::memory_order_acquire);
        int count = 0;
        while (tail != head && count < max_count) {
            __builtin_prefetch(&ring_buffer->ticks[(tail + 2) & (RING_SIZE - 1)], 0, 3);
            out[count++] = ring_buffer->ticks[tail];
            tail = (tail + 1) & (RING_SIZE - 1);
        }
        if (count > 0) ring_buffer->tail.store(tail, std::memory_order_release);
        return count;
    }
};

ApexDaemon* g_daemon = nullptr;
std::atomic<bool> g_shutdown{false};

void sigterm_handler(int) {
    g_shutdown.store(true, std::memory_order_relaxed);
}

int main() {
    ApexDaemon daemon;
    g_daemon = &daemon;

    // Use sigaction instead of signal() — more portable
    struct sigaction sa{};
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);

    std::cout << "[DAEMON] V7.0 Apex Lock-Free Queue Online." << std::endl;

    // Main loop checks atomic flag
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Cleanup runs in main thread context — fully safe
    daemon.running.store(false, std::memory_order_release);
    std::cout << "\n[SHUTDOWN] Executing MS_SYNC on persistent nonce..." << std::endl;
    daemon.checkpoint_nonce_sync_shutdown(
        daemon.mmap_nonce->load(std::memory_order_acquire));

    return 0;
}
