/**
 * Santhosh Chandrasekaran
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include "device.h"
#include "logfs.h"

#define WCACHE_BLOCKS 33
#define RCACHE_BLOCKS 256

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */

struct queue
{
    char *queue_data;
    uint64_t queue_head, queue_tail;
    uint64_t queue_capacity;
    uint64_t queue_utilized;
};

struct worker
{
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int stop_thread;
    int flush_data;
};

struct cache_block
{
    char *data;
    uint64_t offset;
    uint64_t index;
    short valid;
};

struct logfs
{
    struct device *device;
    uint64_t utilized;
    uint64_t capacity;
    struct queue *queue_writer;
    struct worker *worker;
    struct cache_block read_cache[RCACHE_BLOCKS];
};

struct metadata
{
    uint64_t utilized;
};

void reset_cache(struct logfs *logfs, uint64_t offset)
{
    int i;
    for (i = 0; i < RCACHE_BLOCKS; i++)
    {
        if (logfs->read_cache[i].valid && logfs->read_cache[i].offset == offset)
        {
            logfs->read_cache[i].valid = 0;
        }
    }
}

uint64_t reset_block(struct logfs *logfs, uint64_t i)
{
    return i / device_block(logfs->device) * device_block(logfs->device);
}

void disk_write(struct logfs *logfs)
{
    char *buf = logfs->queue_writer->queue_data + logfs->queue_writer->queue_head;
    uint64_t tail = reset_block(logfs, logfs->queue_writer->queue_tail);
    uint64_t utilized_set = reset_block(logfs, logfs->utilized);
    uint64_t offset_device = utilized_set + device_block(logfs->device);
    uint64_t to_write, utilized, i;

    if (logfs->queue_writer->queue_head == tail)
    {
        if (device_write(logfs->device, buf, offset_device, device_block(logfs->device)))
        {
            TRACE("device_write()");
            return;
        }

        reset_cache(logfs, utilized_set);
        logfs->utilized += logfs->queue_writer->queue_utilized;
        logfs->queue_writer->queue_utilized = 0;
    }
    else
    {
        if (logfs->queue_writer->queue_head < tail)
        {
            if (logfs->queue_writer->queue_tail == tail) {
                to_write = logfs->queue_writer->queue_tail - logfs->queue_writer->queue_head;
            }
            else {
                to_write = tail + device_block(logfs->device) - logfs->queue_writer->queue_head;
            }
            utilized = logfs->queue_writer->queue_utilized;
            logfs->queue_writer->queue_head = tail % logfs->queue_writer->queue_capacity;
        }
        else
        {
            to_write = logfs->queue_writer->queue_capacity - logfs->queue_writer->queue_head;
            utilized = logfs->queue_writer->queue_capacity - logfs->queue_writer->queue_head;
            logfs->queue_writer->queue_head = 0;
        }

        if (device_write(logfs->device, buf, offset_device, to_write))
        {
            TRACE("device_write()");
            return;
        }

        for (i = 0; i < to_write / device_block(logfs->device); i++)
        {
            reset_cache(logfs, utilized_set + i * device_block(logfs->device));
        }
        logfs->utilized += utilized;
        logfs->queue_writer->queue_utilized -= utilized;
    }
}

uint64_t get_metadata(struct logfs *logfs)
{
    uint64_t utilized;

    char *metadata = malloc(device_block(logfs->device));
    if (!metadata)
    {
        TRACE("out of memory");
        return -1;
    }

    if (device_read(logfs->device, metadata, 0, device_block(logfs->device)))
    {
        TRACE("device_read()");
        free(metadata);
        return -1;
    }

    utilized = ((struct metadata *)metadata)->utilized;

    free(metadata);

    return utilized;
}

void *create_worker(void *arg)
{
    struct logfs *logfs = arg;

    while (1)
    {
        if (pthread_mutex_lock(&logfs->worker->mutex))
        {
            TRACE("pthread_mutex_lock()");
            return NULL;
        }

        while (logfs->queue_writer->queue_utilized == 0 && !logfs->worker->stop_thread)
        {
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex))
            {
                TRACE("pthread_cond_wait()");
                return NULL;
            }
        }

        if (logfs->queue_writer->queue_utilized >= device_block(logfs->device) || logfs->worker->flush_data)
        {
            disk_write(logfs);

            logfs->worker->flush_data = 0;

            if (pthread_cond_signal(&logfs->worker->cond))
            {
                TRACE("pthread_cond_signal()");
                return NULL;
            }
        }

        if (pthread_mutex_unlock(&logfs->worker->mutex))
        {
            TRACE("pthread_mutex_unlock()");
            return NULL;
        }

        if (logfs->worker->stop_thread)
        {
            return NULL;
        }
    }
}

int setup(struct logfs *logfs, const char *pathname)
{
    int i;

    if (!(logfs->device = device_open(pathname)))
    {
        return -1;
    }

    if (!(logfs->queue_writer = malloc(sizeof(struct queue))))
    {
        return -1;
    }

    if (!(logfs->worker = malloc(sizeof(struct worker))))
    {
        return -1;
    }

    /* Device Setup */
    logfs->capacity = device_size(logfs->device);
    logfs->utilized = get_metadata(logfs);

    /* Queue Setup and Initialization */
    memset(logfs->queue_writer, 0, sizeof(struct queue));

    logfs->queue_writer->queue_head = 0;
    logfs->queue_writer->queue_tail = 0;
    logfs->queue_writer->queue_capacity = device_block(logfs->device) * WCACHE_BLOCKS;
    logfs->queue_writer->queue_utilized = 0;

    if (!(logfs->queue_writer->queue_data = malloc(logfs->queue_writer->queue_capacity)))
    {
        return -1;
    }

    memset(logfs->queue_writer->queue_data, 0, logfs->queue_writer->queue_capacity);

    /* Cache Initialization */
    for (i = 0; i < RCACHE_BLOCKS; i++)
    {
        if (!(logfs->read_cache[i].data = malloc(device_block(logfs->device))))
        {
            return -1;
        }
        memset(logfs->read_cache[i].data, 0, device_block(logfs->device));

        logfs->read_cache[i].valid = 0;
        logfs->read_cache[i].index = i;
    }

    /* Worker Thread Creation */
    memset(logfs->worker, 0, sizeof(struct worker));

    if (pthread_mutex_init(&logfs->worker->mutex, NULL) ||
        pthread_cond_init(&logfs->worker->cond, NULL) ||
        pthread_create(&logfs->worker->thread, NULL, create_worker, logfs))
    {
        return -1;
    }

    return 0;
}

struct logfs *logfs_open(const char *pathname)
{
    struct logfs *logfs;

    assert(safe_strlen(pathname));

    if (!(logfs = malloc(sizeof(struct logfs))))
    {
        TRACE("out of memory");
        return NULL;
    }
    memset(logfs, 0, sizeof(struct logfs));

    if (setup(logfs, pathname))
    {
        logfs_close(logfs);
        TRACE(0);
        return NULL;
    }

    return logfs;
}

void set_metadata(struct logfs *logfs, uint64_t utilized)
{
    char *metadata = malloc(device_block(logfs->device));
    if (!metadata)
    {
        TRACE("out of memory");
        return;
    }

    ((struct metadata *)metadata)->utilized = utilized;

    if (device_write(logfs->device, metadata, 0, device_block(logfs->device)))
    {
        TRACE("device_write()");
        free(metadata);
        return;
    }

    free(metadata);
}

void logfs_close(struct logfs *logfs)
{
    int i;

    assert(logfs);

    set_metadata(logfs, logfs->utilized);

    if (logfs)
    {
        if (logfs->worker)
        {
            if (pthread_mutex_lock(&logfs->worker->mutex))
            {
                TRACE("pthread_mutex_lock()");
            }
            logfs->worker->stop_thread = 1;
            if (pthread_cond_signal(&logfs->worker->cond))
            {
                TRACE("pthread_cond_signal()");
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex))
            {
                TRACE("pthread_mutex_unlock()");
            }
            if (pthread_join(logfs->worker->thread, NULL))
            {
                TRACE("pthread_join()");
            }
            if (pthread_mutex_destroy(&logfs->worker->mutex))
            {
                TRACE("pthread_mutex_destroy()");
            }
            if (pthread_cond_destroy(&logfs->worker->cond))
            {
                TRACE("pthread_cond_destroy()");
            }
        }
        if (logfs->queue_writer)
        {
            FREE(logfs->queue_writer->queue_data);
            FREE(logfs->queue_writer);
        }
        for (i = 0; i < RCACHE_BLOCKS; ++i)
        {
            if (logfs->read_cache[i].data)
            {
                FREE(logfs->read_cache[i].data);
            }
        }
        if (logfs->worker)
        {
            FREE(logfs->worker);
        }
        if (logfs->queue_writer)
        {
            FREE(logfs->queue_writer);
        }
        if (logfs->device)
        {
            device_close(logfs->device);
        }
        memset(logfs, 0, sizeof(struct logfs));
    }
    FREE(logfs);
}

int cache_data(struct logfs *logfs, void *buf, uint64_t block_offset, uint64_t data_offset, uint64_t to_read)
{
    int i;
    for (i = 0; i < RCACHE_BLOCKS; i++)
    {
        if (logfs->read_cache[i].valid && logfs->read_cache[i].offset == block_offset - device_block(logfs->device))
        {
            memcpy(buf, logfs->read_cache[i].data + data_offset, to_read);
            return 0;
        }
    }
    return -1;
}

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len)
{
    uint64_t written, start_block_offset, end_block_offset;
    int num_blocks, i;
    char *result;

    if (!buf || !len)
    {
        return 0;
    }

    off += device_block(logfs->device);

    while (1)
    {
        if (pthread_mutex_lock(&logfs->worker->mutex))
        {
            TRACE("pthread_mutex_lock()");
            return -1;
        }

        while (logfs->queue_writer->queue_utilized > 0)
        {
            if (logfs->queue_writer->queue_utilized < device_block(logfs->device))
            {
                logfs->worker->flush_data = 1;
            }
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex))
            {
                TRACE("pthread_cond_wait()");
                return -1;
            }
        }

        if (logfs->queue_writer->queue_utilized == 0)
        {
            if (pthread_cond_signal(&logfs->worker->cond))
            {
                TRACE("pthread_cond_signal()");
                return -1;
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex))
            {
                TRACE("pthread_mutex_unlock()");
                return -1;
            }
            break;
        }

        if (pthread_mutex_unlock(&logfs->worker->mutex))
        {
            TRACE("pthread_mutex_unlock()");
            return -1;
        }
    }

    written = 0;
    start_block_offset = reset_block(logfs, off);
    end_block_offset = reset_block(logfs, off + len);
    num_blocks = (int)((end_block_offset - start_block_offset) / device_block(logfs->device)) + 1;

    result = malloc(len);

    for (i = 0; i < num_blocks; i++)
    {
        uint64_t block_offset = start_block_offset + i * device_block(logfs->device);
        uint64_t data_offset, to_read;

        if (i == 0)
        {
            data_offset = off - start_block_offset;
            to_read = MIN(device_block(logfs->device) - data_offset, len);
        }
        else if (i == num_blocks - 1)
        {
            data_offset = 0;
            to_read = off + len - end_block_offset;
        }
        else
        {
            data_offset = 0;
            to_read = device_block(logfs->device);
        }

        if (cache_data(logfs, result + written, block_offset, data_offset, to_read) != 0)
        {
            int min_index = 0, max_index = 0, j;
            char *data;

            for (j = 0; j < RCACHE_BLOCKS; j++)
            {
                if (logfs->read_cache[j].index < logfs->read_cache[min_index].index)
                {
                    min_index = j;
                }
                if (logfs->read_cache[j].index > logfs->read_cache[max_index].index)
                {
                    max_index = j;
                }
            }

            data = malloc(device_block(logfs->device));
            if (!data)
            {
                TRACE("out of memory");
                return -1;
            }

            if (device_read(logfs->device, data, block_offset, device_block(logfs->device)))
            {
                TRACE("device_read()");
                return -1;
            }

            memcpy(logfs->read_cache[min_index].data, data, device_block(logfs->device));
            logfs->read_cache[min_index].offset = block_offset - device_block(logfs->device);
            logfs->read_cache[min_index].valid = 1;
            logfs->read_cache[min_index].index = logfs->read_cache[max_index].index + 1;

            free(data);

            memcpy(result + written, logfs->read_cache[min_index].data + data_offset, to_read);
        }

        written += to_read;
    }

    memcpy(buf, result, len);

    free(result);

    return 0;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len)
{
    assert(logfs);
    assert(buf || !len);

    if (logfs->utilized + len > logfs->capacity)
    {
        TRACE("out of space");
        return -1;
    }

    while (1)
    {
        if (pthread_mutex_lock(&logfs->worker->mutex))
        {
            TRACE("pthread_mutex_lock()");
            return -1;
        }

        while (logfs->queue_writer->queue_utilized + len > logfs->queue_writer->queue_capacity)
        {
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex))
            {
                TRACE("pthread_cond_wait()");
                return -1;
            }
        }

        if (logfs->queue_writer->queue_utilized + len <= logfs->queue_writer->queue_capacity)
        {
            if (logfs->queue_writer->queue_tail + len <= logfs->queue_writer->queue_capacity)
            {
                memcpy(logfs->queue_writer->queue_data + logfs->queue_writer->queue_tail, buf, len);
                logfs->queue_writer->queue_tail += len;
            }
            else
            {
                uint64_t end_space = logfs->queue_writer->queue_capacity - logfs->queue_writer->queue_tail;
                uint64_t remaining_space = len - end_space;
                if (end_space)
                {
                    memcpy(logfs->queue_writer->queue_data + logfs->queue_writer->queue_tail, buf, end_space);
                }
                if (remaining_space)
                {
                    memcpy(logfs->queue_writer->queue_data, (char *)buf + end_space, remaining_space);
                }
                logfs->queue_writer->queue_tail = remaining_space % logfs->queue_writer->queue_capacity;
            }

            logfs->queue_writer->queue_utilized += len;

            if (pthread_cond_signal(&logfs->worker->cond))
            {
                TRACE("pthread_cond_signal()");
                return -1;
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex))
            {
                TRACE("pthread_mutex_unlock()");
                return -1;
            }
            return 0;
        }
    }

    return 0;
}

uint64_t logfs_size(struct logfs *logfs)
{
    assert(logfs);

    return logfs->utilized;
}
