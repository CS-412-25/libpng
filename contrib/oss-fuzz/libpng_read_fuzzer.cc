// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#include "png.h"

#define SAFE_DEREF(ptr) {if ((ptr) != NULL) *(ptr);}

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}

static const int kPngHeaderSize = 8;

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }

  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;

  png_handler.png_ptr = png_create_read_struct
    (PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Use a custom allocator that fails for large allocations to avoid OOM.
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

  // Setting up reading from buffer.
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  // Reading.
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // reset error handler to put png_deleter into scope.
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type;
  int filter_type;

  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP
    return 0;
  }

  // This is going to be too slow.
  if (width && height > 100000000 / width) {
    PNG_CLEANUP
    return 0;
  }

  // Set several transforms that browsers typically use:
  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  // TODO: tmp call all getters
  png_get_valid(png_handler.png_ptr, png_handler.info_ptr, 0);
  png_get_rows(png_handler.png_ptr, png_handler.info_ptr);
  png_get_image_width(png_handler.png_ptr, png_handler.info_ptr);
  png_get_image_height(png_handler.png_ptr, png_handler.info_ptr);
  png_get_bit_depth(png_handler.png_ptr, png_handler.info_ptr);
  png_get_color_type(png_handler.png_ptr, png_handler.info_ptr);
  png_get_filter_type(png_handler.png_ptr, png_handler.info_ptr);
  png_get_interlace_type(png_handler.png_ptr, png_handler.info_ptr);
  png_get_compression_type(png_handler.png_ptr, png_handler.info_ptr);
  png_get_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
  png_get_x_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
  png_get_y_pixels_per_meter(png_handler.png_ptr, png_handler.info_ptr);
  png_get_pixel_aspect_ratio(png_handler.png_ptr, png_handler.info_ptr);
  png_get_pixel_aspect_ratio_fixed(png_handler.png_ptr, png_handler.info_ptr);
  png_get_x_offset_pixels(png_handler.png_ptr, png_handler.info_ptr);
  png_get_y_offset_pixels(png_handler.png_ptr, png_handler.info_ptr);
  png_get_x_offset_microns(png_handler.png_ptr, png_handler.info_ptr);
  png_get_y_offset_microns(png_handler.png_ptr, png_handler.info_ptr);
  png_get_pixels_per_inch(png_handler.png_ptr, png_handler.info_ptr);
  png_get_x_pixels_per_inch(png_handler.png_ptr, png_handler.info_ptr);
  png_get_y_pixels_per_inch(png_handler.png_ptr, png_handler.info_ptr);
  png_get_x_offset_inches(png_handler.png_ptr, png_handler.info_ptr);
  png_get_y_offset_inches(png_handler.png_ptr, png_handler.info_ptr);
  png_get_signature(png_handler.png_ptr, png_handler.info_ptr);
  png_get_channels(png_handler.png_ptr, png_handler.info_ptr);

  // TODO: double check if this doesn't optimize away the deref
  volatile png_color_16p color_info;
  png_get_bKGD(png_handler.png_ptr, png_handler.info_ptr, (png_color_16pp)&color_info);
  SAFE_DEREF(color_info)

  double values[9];
  png_get_cHRM(png_handler.png_ptr, png_handler.info_ptr, &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7]);

  png_get_cHRM_XYZ(png_handler.png_ptr, png_handler.info_ptr, &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8]);

  png_fixed_point values_fixed[9];
  png_get_cHRM_XYZ_fixed(png_handler.png_ptr, png_handler.info_ptr,&values_fixed[0], &values_fixed[1], &values_fixed[2], &values_fixed[3], &values_fixed[4], &values_fixed[5], &values_fixed[6], &values_fixed[7], &values_fixed[8]);

  png_get_gAMA_fixed(png_handler.png_ptr, png_handler.info_ptr, &values_fixed[0]);
  png_get_gAMA(png_handler.png_ptr, png_handler.info_ptr, &values[0]);

  int random_int;
  png_get_sRGB(png_handler.png_ptr, png_handler.info_ptr, &random_int);

  volatile png_charp iccp_name;
  int iccp_compression_type;
  volatile png_bytep iccp_profile;
  png_uint_32 iccp_profile_len;

  png_get_iCCP(png_handler.png_ptr, png_handler.info_ptr, (png_charpp)&iccp_name, &iccp_compression_type, (png_bytepp)&iccp_profile, &iccp_profile_len);
  SAFE_DEREF(iccp_name)
  for (png_uint_32 cnt = 0; cnt < iccp_profile_len && iccp_profile != NULL; ++cnt) {
      SAFE_DEREF(iccp_profile + cnt)
  }

  png_sPLT_tp splt_pointer;
  png_get_sPLT(png_handler.png_ptr, png_handler.info_ptr, &splt_pointer);

  png_byte cicp_1, cicp_2, cicp_3, cicp_4;
  png_get_cICP(png_handler.png_ptr, png_handler.info_ptr, &cicp_1, &cicp_2, &cicp_3, &cicp_4);

  png_uint_32 clli_1_f, clli_2_f;
  png_get_cLLI_fixed(png_handler.png_ptr, png_handler.info_ptr, &clli_1_f, &clli_2_f);

  double clli_1, clli_2;
  png_get_cLLI(png_handler.png_ptr, png_handler.info_ptr, &clli_1, &clli_2);

  png_fixed_point mdcv_ptrs[8];
  png_uint_32 mdcv_uints[2];
  png_get_mDCV_fixed(png_handler.png_ptr, png_handler.info_ptr,&mdcv_ptrs[0], &mdcv_ptrs[1], &mdcv_ptrs[2], &mdcv_ptrs[3], &mdcv_ptrs[4], &mdcv_ptrs[5], &mdcv_ptrs[6], &mdcv_ptrs[7], &mdcv_uints[0], &mdcv_uints[1]);

  double mdcv_doubles[10];
  png_get_mDCV(png_handler.png_ptr, png_handler.info_ptr,&mdcv_doubles[0], &mdcv_doubles[1], &mdcv_doubles[2], &mdcv_doubles[3], &mdcv_doubles[4], &mdcv_doubles[5], &mdcv_doubles[6], &mdcv_doubles[7], &mdcv_doubles[0], &mdcv_doubles[1]);

  volatile png_bytep exif_ptr;
  png_get_eXIf(png_handler.png_ptr, png_handler.info_ptr, (png_bytepp)&exif_ptr);
  SAFE_DEREF(exif_ptr)

  volatile png_uint_32 exif_cnt;
  png_get_eXIf_1(png_handler.png_ptr, png_handler.info_ptr, (png_uint_32p)&exif_cnt, &exif_ptr);
  SAFE_DEREF(exif_ptr)

  volatile png_uint_16p hist_ptr;
  png_get_hIST(png_handler.png_ptr, png_handler.info_ptr, (png_uint_16pp)&hist_ptr);
  SAFE_DEREF(hist_ptr)

  png_int_32 offs_ptrs[2];
  int offs_int;
  png_get_oFFs(png_handler.png_ptr, png_handler.info_ptr, &offs_ptrs[0], &offs_ptrs[1], &offs_int);

  volatile png_charp pcal_char[2];
  png_int_32 pcal_int[2];
  int pcal_int2[2];
  volatile png_charpp pcal_params;

  png_get_pCAL(png_handler.png_ptr, png_handler.info_ptr, (png_charpp)&pcal_char[0], &pcal_int[0], &pcal_int[1], &pcal_int2[0], &pcal_int2[1], (png_charpp)&pcal_char[1], (png_charpp*)&pcal_params);
  SAFE_DEREF(pcal_char)
  SAFE_DEREF(pcal_char + 1)
  SAFE_DEREF(pcal_params)

  int scal_int_f;
  png_fixed_point scal_ptrs_f[2];
  png_get_sCAL_fixed(png_handler.png_ptr, png_handler.info_ptr, &scal_int_f, &scal_ptrs_f[0], &scal_ptrs_f[1]);

  int scals_unit;
  volatile png_charp scals_ptrs[2];
  png_get_sCAL_s(png_handler.png_ptr, png_handler.info_ptr, &scals_unit, (png_charpp)&scals_ptrs[0], (png_charpp)&scals_ptrs[1]);
  SAFE_DEREF(scals_ptrs)
  SAFE_DEREF(scals_ptrs + 1)

  png_uint_32 phys_ptrs[2];
  int phys_int;
  png_get_pHYs(png_handler.png_ptr, png_handler.info_ptr, &phys_ptrs[0], &phys_ptrs[1], &phys_int);

  volatile png_colorp plte_color;
  int plte_int;
  png_get_PLTE(png_handler.png_ptr, png_handler.info_ptr, (png_colorpp)&plte_color, &plte_int);
  for (int cnt = 0; cnt < plte_int && plte_color != NULL; ++cnt) {
      SAFE_DEREF(plte_color + cnt)
  }

  volatile png_color_8p sbit_stuff;
  png_get_sBIT(png_handler.png_ptr, png_handler.info_ptr, (png_color_8pp)&sbit_stuff);
  SAFE_DEREF(sbit_stuff)

  volatile png_textp text_ptr;
  int text_len;
  png_get_text(png_handler.png_ptr, png_handler.info_ptr, (png_textpp)&text_ptr, &text_len);
  for (int cnt = 0; cnt < text_len && text_ptr != NULL; ++cnt) {
      SAFE_DEREF(text_ptr + cnt)
  }

  volatile png_timep time_ptr;
  png_get_tIME(png_handler.png_ptr, png_handler.info_ptr, (png_timepp)&time_ptr);
  SAFE_DEREF(time_ptr)

  png_bytep trns_ptr;
  int trns_int;
  png_color_16p trns_color;
  png_get_tRNS(png_handler.png_ptr, png_handler.info_ptr, &trns_ptr, &trns_int, &trns_color);

  volatile png_unknown_chunkp unk_ptr;
  png_get_unknown_chunks(png_handler.png_ptr, png_handler.info_ptr, (png_unknown_chunkpp)&unk_ptr);
  SAFE_DEREF(unk_ptr)

  png_get_rgb_to_gray_status(png_handler.png_ptr);
  png_get_user_chunk_ptr(png_handler.png_ptr);
  png_get_compression_buffer_size(png_handler.png_ptr);
  png_get_user_width_max(png_handler.png_ptr);
  png_get_user_height_max(png_handler.png_ptr);
  png_get_chunk_cache_max(png_handler.png_ptr);
  png_get_chunk_malloc_max(png_handler.png_ptr);
  png_get_io_state(png_handler.png_ptr);
  png_get_io_chunk_type(png_handler.png_ptr);
  png_get_palette_max(png_handler.png_ptr, png_handler.info_ptr);

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr,
                                            png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  PNG_CLEANUP

#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
  // Simplified READ API
  png_image image;
  memset(&image, 0, (sizeof image));
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    return 0;
  }

  image.format = PNG_FORMAT_RGBA;
  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
  png_image_finish_read(&image, NULL, buffer.data(), 0, NULL);
#endif

  return 0;
}
