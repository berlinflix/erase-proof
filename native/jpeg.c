/* Strict bounded libjpeg validation for fragment hypotheses. No file writes. */
#include <stdio.h>
#include <jpeglib.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

struct errors {
    struct jpeg_error_mgr base;
    jmp_buf escape;
    unsigned int warnings;
    unsigned long size;
    unsigned long position;
};

static void fail(j_common_ptr decoder) {
    struct errors *error = (struct errors *)decoder->err;
    struct jpeg_decompress_struct *source = (struct jpeg_decompress_struct *)decoder;
    if (source->src) error->position = error->size-source->src->bytes_in_buffer;
    longjmp(error->escape, 1);
}

static void message(j_common_ptr decoder, int level) {
    struct errors *error = (struct errors *)decoder->err;
    if (level < 0) {
        error->warnings++;
        fail(decoder); /* Fail immediately; no repeated full corrupt decodes. */
    }
}

int ep_jpeg_probe(const unsigned char *data, unsigned long size, unsigned long *position) {
    struct jpeg_decompress_struct decoder = {0};
    struct errors error = {0};
    JSAMPARRAY row;
    if (!data || size < 32 || size > 32UL*1024*1024) return 0;
    decoder.err = jpeg_std_error(&error.base);
    error.base.error_exit = fail;
    error.base.emit_message = message;
    error.warnings = 0;
    error.size = size;
    if (position) *position = 0;
    if (setjmp(error.escape)) {
        if (position) *position = error.position;
        jpeg_destroy_decompress(&decoder);
        return 0;
    }
    jpeg_create_decompress(&decoder);
    decoder.mem->max_memory_to_use = 64L*1024*1024;
    jpeg_mem_src(&decoder, data, size);
    if (jpeg_read_header(&decoder, TRUE) != JPEG_HEADER_OK ||
        !decoder.image_width || !decoder.image_height ||
        (uint64_t)decoder.image_width*decoder.image_height > 25000000) {
        jpeg_destroy_decompress(&decoder);
        return 0;
    }
    jpeg_start_decompress(&decoder);
    row = (*decoder.mem->alloc_sarray)((j_common_ptr)&decoder, JPOOL_IMAGE,
                                       decoder.output_width*decoder.output_components, 1);
    while (decoder.output_scanline < decoder.output_height) {
        if (jpeg_read_scanlines(&decoder, row, 1) != 1) fail((j_common_ptr)&decoder);
    }
    jpeg_finish_decompress(&decoder);
    jpeg_destroy_decompress(&decoder);
    return error.warnings == 0;
}

int ep_jpeg_valid(const unsigned char *data, unsigned long size) {
    return ep_jpeg_probe(data, size, NULL);
}
