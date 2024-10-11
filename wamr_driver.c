/*
 * This file is part of AtomVM WAMR driver
 *
 * Copyright 2024 Davide Bettio <davide@uninstall.it>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <esp_log.h>

#include <context.h>
#include <defaultatoms.h>
#include <externalterm.h>
#include <interop.h>

#include <esp32_sys.h>

#include <bh_platform.h>
#include <wasm_export.h>

#define LOG_TAG "wamr"

static int wamr_counter;

struct WASMArgs
{
    Context *ctx;
    QueueHandle_t wamr_messages_queue;

    size_t size;
    void *ptr;

    bool start_paused;
};

static int64_t awamr_make_u64_ref(wasm_exec_env_t exec_env);
static int32_t awamr_send_term(wasm_exec_env_t exec_env, int id, uint8_t *buf, int buf_len);
static uint32_t awamr_receive_term_buffer(wasm_exec_env_t exec_env);

static NativeSymbol native_symbols[] = {
    { .symbol = "make_u64_ref",
        .func_ptr = awamr_make_u64_ref,
        .signature = "()I",
        .attachment = NULL },
    { .symbol = "send_term",
        .func_ptr = awamr_send_term,
        .signature = "(i*~)i",
        .attachment = NULL },
    { .symbol = "receive_term_buffer",
        .func_ptr = awamr_receive_term_buffer,
        .signature = "()i",
        .attachment = NULL }
};

static int64_t awamr_make_u64_ref(wasm_exec_env_t exec_env)
{
    struct WASMArgs *wargs = wasm_runtime_get_user_data(exec_env);
    GlobalContext *glb = wargs->ctx->global;

    uint64_t ref_ticks = globalcontext_get_ref_ticks(glb);

    return (int64_t) ref_ticks;
}

static int32_t awamr_send_term(wasm_exec_env_t exec_env, int id, uint8_t *buf, int buf_len)
{
    struct WASMArgs *wargs = wasm_runtime_get_user_data(exec_env);
    Context *ctx = wargs->ctx;

    BEGIN_WITH_STACK_HEAP(1, temp_heap);

    term t;
    if ((buf[0] == 131) && (buf[1] == 1)) {
        uint8_t envelope_size = buf[2];

        {
            Heap heap;
            if (UNLIKELY(memory_init_heap(&heap, TUPLE_SIZE(envelope_size)) != MEMORY_GC_OK)) {
                END_WITH_STACK_HEAP(temp_heap, ctx->global);
                return term_invalid_term();
            }
            t = term_alloc_tuple(envelope_size, &heap);
            memory_heap_append_heap(&temp_heap, &heap);
        }

        buf += 3;

        for (int i = 0; i < envelope_size; i++) {
            switch (buf[0]) {
                case 2:
                    uint32_t tlen = READ_32_UNALIGNED(buf + 1);
                    term element = externalterm_to_term_copy(
                        buf + 5, buf_len, ctx, ExternalTermToHeapFragment);
                    term_put_tuple_element(t, i, element);
                    buf += 5 + tlen;
                    break;
                case 3:
                    int32_t ipid = READ_32_UNALIGNED(buf + 1);
                    term pid;
                    if (ipid == -1) {
                        pid = term_from_local_process_id(ctx->process_id);
                    } else {
                        abort();
                    }
                    term_put_tuple_element(t, i, pid);
                    buf += 5;
                    break;
                case 4:
                    uint64_t iref = READ_64_UNALIGNED(buf + 1);

                    term ref;
                    {
                        Heap heap;
                        if (UNLIKELY(memory_init_heap(&heap, REF_SIZE) != MEMORY_GC_OK)) {
                            END_WITH_STACK_HEAP(temp_heap, ctx->global);
                            return term_invalid_term();
                        }
                        ref = term_from_ref_ticks(iref, &heap);
                        memory_heap_append_heap(&temp_heap, &heap);
                    }
                    term_put_tuple_element(t, i, ref);

                    buf += 9;
                    break;
            }
        }
    } else {
        t = externalterm_to_term_copy(buf, buf_len, ctx, ExternalTermToHeapFragment);
    }

    if ((id == 0) && (ctx->group_leader != term_invalid_term())) {
        int32_t local_id = term_to_local_process_id(ctx->group_leader);
        globalcontext_send_message(ctx->global, local_id, t);
    }

    END_WITH_STACK_HEAP(temp_heap, ctx->global);

    return 0;
}

static uint32_t awamr_receive_term_buffer(wasm_exec_env_t exec_env)
{
    struct WASMArgs *wargs = wasm_runtime_get_user_data(exec_env);

    GlobalContext *glb = wargs->ctx->global;

    Message *message;
    xQueueReceive(wargs->wamr_messages_queue, &message, portMAX_DELAY);

    size_t et_size;
    if (externalterm_compute_external_size_raw(message->message, &et_size, glb)
        != EXTERNAL_TERM_OK) {
        abort();
    }

    uint32_t ext_len = (uint32_t) et_size;
    size_t buf_len = sizeof(uint32_t) + ext_len;

    void *buffer = NULL;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint64_t buffer_for_wasm = wasm_runtime_module_malloc(module_inst, buf_len, &buffer);

    memcpy(buffer, &ext_len, sizeof(uint32_t));
    if (externalterm_serialize_term_raw(
            ((uint8_t *) buffer) + sizeof(uint32_t), message->message, glb)
        != EXTERNAL_TERM_OK) {
        abort();
    }

    BEGIN_WITH_STACK_HEAP(1, temp_heap);
    mailbox_message_dispose(&message->base, &temp_heap);
    END_WITH_STACK_HEAP(temp_heap, glb);

    return (uint32_t) buffer_for_wasm;
}

static void wait_start(struct WASMArgs *wargs)
{
    GlobalContext *glb = wargs->ctx->global;

    bool exit = false;
    while (!exit) {
        Message *message;
        xQueueReceive(wargs->wamr_messages_queue, &message, portMAX_DELAY);

        if (message->message
            == globalcontext_existing_term_from_atom_string(glb, ATOM_STR("\x5", "start"))) {
            exit = true;
        }

        BEGIN_WITH_STACK_HEAP(1, temp_heap);
        mailbox_message_dispose(&message->base, &temp_heap);
        END_WITH_STACK_HEAP(temp_heap, glb);
    }
}

static void run_wasm_app_main(wasm_module_inst_t module_inst)
{
    const char *exception;

    wasm_application_execute_main(module_inst, 0, NULL);
    if ((exception = wasm_runtime_get_exception(module_inst))) {
        ESP_LOGW(LOG_TAG, "WASM exception: %s\n", exception);
    }
}

static bool ensure_wamr()
{
    wamr_counter++;
    if (wamr_counter > 1) {
        return true;
    }

    RuntimeInitArgs init_args;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = (void *) os_malloc;
    init_args.mem_alloc_option.allocator.realloc_func = (void *) os_realloc;
    init_args.mem_alloc_option.allocator.free_func = (void *) os_free;

    ESP_LOGI(LOG_TAG, "Initializing WASM runtime");
    if (!wasm_runtime_full_init(&init_args)) {
        ESP_LOGE(LOG_TAG, "Runtime init failed");
        wamr_counter = 0;
        return false;
    }

    int n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    if (!wasm_runtime_register_natives("env", native_symbols, n_native_symbols)) {
        abort();
    }

    return true;
}

static void release_wamr()
{
    wamr_counter--;

    if (wamr_counter == 0) {
        ESP_LOGI(LOG_TAG, "Destroying WASM runtime");
        wasm_runtime_destroy();
    }
}

static void *wasm_main(void *arg)
{
    if (!ensure_wamr()) {
        return NULL;
    }

    struct WASMArgs *wargs = arg;

    uint8_t *wasm_file_buf = wargs->ptr;
    unsigned wasm_file_buf_size = wargs->size;

    ESP_LOGI(LOG_TAG, "Running wamr with interpreter");
    char error_buf[128];
    wasm_module_t wasm_module;
    if (!(wasm_module
            = wasm_runtime_load(wasm_file_buf, wasm_file_buf_size, error_buf, sizeof(error_buf)))) {
        ESP_LOGE(LOG_TAG, "Error in wasm_runtime_load: %s", error_buf);
        goto release_and_return;
    }

    ESP_LOGI(LOG_TAG, "Instantiating WASM runtime");
    wasm_module_inst_t wasm_module_inst;
    if (!(wasm_module_inst = wasm_runtime_instantiate(wasm_module, 32 * 1024, // stack size
              32 * 1024, // heap size
              error_buf, sizeof(error_buf)))) {
        ESP_LOGE(LOG_TAG, "Error while instantiating: %s", error_buf);
        goto unload_and_return;
    }

    wasm_exec_env_t exec_env = wasm_runtime_get_exec_env_singleton(wasm_module_inst);
    wasm_runtime_set_user_data(exec_env, wargs);

    if (wargs->start_paused) {
        ESP_LOGI(LOG_TAG, "Waiting start signal");
        wait_start(wargs);
    }

    ESP_LOGI(LOG_TAG, "Running app");
    run_wasm_app_main(wasm_module_inst);

    ESP_LOGI(LOG_TAG, "Deinstantiating WASM runtime");
    wasm_runtime_deinstantiate(wasm_module_inst);

unload_and_return:
    ESP_LOGI(LOG_TAG, "Unloading WASM module");
    wasm_runtime_unload(wasm_module);

    // TODO: release resources

release_and_return:
    release_wamr();

    return NULL;
}

static NativeHandlerResult wamr_driver_consume_mailbox(Context *ctx)
{
    MailboxMessage *mbox_msg = mailbox_take_message(&ctx->mailbox);
    Message *msg = CONTAINER_OF(mbox_msg, Message, base);

    struct WASMArgs *wargs = ctx->platform_data;

    xQueueSend(wargs->wamr_messages_queue, &msg, 1);

    return NativeContinue;
}

Context *wamr_create_port(GlobalContext *global, term opts)
{
    Context *ctx = context_new(global);
    ctx->native_handler = wamr_driver_consume_mailbox;

    struct WASMArgs *wargs = malloc(sizeof(struct WASMArgs));
    if (IS_NULL_PTR(wargs)) {
        abort();
    }
    ctx->platform_data = wargs;

    wargs->wamr_messages_queue = xQueueCreate(32, sizeof(Message *));

    pthread_attr_t tattr;
    pthread_attr_init(&tattr);
    pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setstacksize(&tattr, 4096);

    term wasm_bin = interop_kv_get_value_default(
        opts, ATOM_STR("\x4", "wasm"), term_invalid_term(), ctx->global);
    if (!term_is_binary(wasm_bin)) {
        abort();
    }

    term start_paused = interop_kv_get_value_default(
        opts, ATOM_STR("\xC", "start_paused"), FALSE_ATOM, ctx->global);
    if ((start_paused != TRUE_ATOM) && (start_paused != FALSE_ATOM)) {
        abort();
    }
    wargs->start_paused = start_paused == TRUE_ATOM;

    wargs->ctx = ctx;
    wargs->size = term_binary_size(wasm_bin);
    wargs->ptr = malloc(wargs->size);
    if (IS_NULL_PTR(wargs->ptr)) {
        abort();
    }
    memcpy(wargs->ptr, term_binary_data(wasm_bin), wargs->size);

    pthread_t t;
    int res = pthread_create(&t, &tattr, wasm_main, wargs);
    if (res != 0) {
        abort();
    }

    return ctx;
}

REGISTER_PORT_DRIVER(wamr, NULL, NULL, wamr_create_port)
