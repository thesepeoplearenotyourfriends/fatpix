#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

tmp=${TMPDIR:-/tmp}/garble-clarity-test.$$
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp"
mkdir -p "$tmp/kaitai/filesystem"
cat > "$tmp/kaitai/filesystem/mbr_partition_table.ksy" <<'KSY'
meta:
  id: mbr_partition_table
  title: MBR (Master Boot Record) partition table
  license: CC0-1.0
  endian: le
  doc: |
    MBR partition-table structure used as an external Clarity shape definition.
seq:
  - id: bootstrap_code
    size: 0x1be
  - id: partitions
    type: partition_entry
    repeat: expr
    repeat-expr: 4
  - id: boot_signature
    contents: [0x55, 0xaa]
types:
  partition_entry:
    seq:
      - id: status
        type: u1
      - id: chs_start
        type: chs
      - id: partition_type
        type: u1
      - id: chs_end
        type: chs
      - id: lba_start
        type: u4
      - id: num_sectors
        type: u4
  chs:
    seq:
      - id: head
        type: u1
      - id: b2
        type: u1
      - id: b3
        type: u1
    instances:
      sector:
        value: 'b2 & 0b111111'
      cylinder:
        value: 'b3 + ((b2 & 0b11000000) << 2)'
KSY
cat > "$tmp/kaitai/filesystem/gpt_partition_table.ksy" <<'KSY'
meta:
  id: gpt_partition_table
  title: GPT (GUID) partition table
  endian: le
instances:
  sector_size:
    value: 0x200
  primary:
    io: _root._io
    pos: _root.sector_size
    type: partition_header
  backup:
    io: _root._io
    pos: _io.size - _root.sector_size
    type: partition_header
types:
  partition_entry:
    seq:
      - id: type_guid
        size: 0x10
      - id: guid
        size: 0x10
      - id: first_lba
        type: u8
      - id: last_lba
        type: u8
      - id: attributes
        type: u8
      - id: name
        type: str
        encoding: UTF-16LE
        size: 0x48
  partition_header:
    seq:
      - id: signature
        contents: [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54]
      - id: revision
        type: u4
      - id: header_size
        type: u4
      - id: crc32_header
        type: u4
      - id: reserved
        type: u4
      - id: current_lba
        type: u8
      - id: backup_lba
        type: u8
      - id: first_usable_lba
        type: u8
      - id: last_usable_lba
        type: u8
      - id: disk_guid
        size: 0x10
      - id: entries_start
        type: u8
      - id: entries_count
        type: u4
      - id: entries_size
        type: u4
      - id: crc32_array
        type: u4
    instances:
      entries:
        io: _root._io
        pos: entries_start * _root.sector_size
        size: entries_size
        type: partition_entry
        repeat: expr
        repeat-expr: entries_count
KSY
mkdir -p "$tmp/kaitai/game" "$tmp/kaitai/archive"
cat > "$tmp/kaitai/game/quake_pak.ksy" <<'KSY'
meta:
  id: quake_pak
  endian: le
seq:
  - id: magic
    contents: 'PACK'
  - id: ofs_index
    type: u4
  - id: len_index
    type: u4
instances:
  index:
    pos: ofs_index
    size: len_index
    type: index_struct
types:
  index_struct:
    seq:
      - id: entries
        type: index_entry
        repeat: eos
  index_entry:
    seq:
      - id: name
        type: str
        size: 56
        encoding: UTF-8
        terminator: 0
        pad-right: 0
      - id: ofs
        type: u4
      - id: size
        type: u4
    instances:
      body:
        io: _root._io
        pos: ofs
        size: size
KSY
cat > "$tmp/kaitai/archive/cpio_old_le.ksy" <<'KSY'
meta:
  id: cpio_old_le
  endian: le
seq:
  - id: files
    type: file
    repeat: eos
types:
  file:
    seq:
      - id: header
        type: file_header
      - id: path_name
        size: header.path_name_size - 1
      - id: string_terminator
        contents: [0x00]
      - id: path_name_padding
        contents: [0x00]
        if: header.path_name_size % 2 == 1
      - id: file_data
        size: header.file_size.value
      - id: file_data_padding
        contents: [0x00]
        if: header.file_size.value % 2 == 1
      - id: end_of_file_padding
        size-eos: true
        if: path_name == [0x54, 0x52, 0x41, 0x49, 0x4c, 0x45, 0x52, 0x21, 0x21, 0x21] and header.file_size.value == 0
  file_header:
    seq:
      - id: magic
        contents: [0xC7, 0x71]
      - id: device_number
        type: u2
      - id: inode_number
        type: u2
      - id: mode
        type: u2
      - id: user_id
        type: u2
      - id: group_id
        type: u2
      - id: number_of_links
        type: u2
      - id: r_device_number
        type: u2
      - id: modification_time
        type: four_byte_unsigned_integer
      - id: path_name_size
        type: u2
      - id: file_size
        type: four_byte_unsigned_integer
  four_byte_unsigned_integer:
    seq:
      - id: most_significant_bits
        type: u2
      - id: least_significant_bits
        type: u2
    instances:
      value:
        value: least_significant_bits + (most_significant_bits << 16)
KSY
cat > "$tmp/kaitai/archive/gzip.ksy" <<'KSY'
meta:
  id: gzip
  endian: le
seq:
  - id: magic
    contents: [0x1f, 0x8b]
  - id: compression_method
    type: u1
    enum: compression_methods
  - id: flags
    type: flags
  - id: mod_time
    type: u4
  - id: extra_flags
    type:
      switch-on: compression_method
      cases:
        'compression_methods::deflate': extra_flags_deflate
  - id: os
    type: u1
  - id: extras
    type: extras
    if: flags.has_extra
  - id: name
    terminator: 0
    if: flags.has_name
  - id: comment
    terminator: 0
    if: flags.has_comment
  - id: header_crc16
    type: u2
    if: flags.has_header_crc
  - id: body
    size: _io.size - _io.pos - 8
  - id: body_crc32
    type: u4
  - id: len_uncompressed
    type: u4
enums:
  compression_methods:
    8: deflate
types:
  flags:
    seq:
      - id: reserved1
        type: b3
      - id: has_comment
        type: b1
      - id: has_name
        type: b1
      - id: has_extra
        type: b1
      - id: has_header_crc
        type: b1
      - id: is_text
        type: b1
  extra_flags_deflate:
    seq:
      - id: compression_strength
        type: u1
  extras:
    seq:
      - id: len_subfields
        type: u2
      - id: subfields
        size: len_subfields
        type: subfields
  subfields:
    seq:
      - id: entries
        type: subfield
        repeat: eos
  subfield:
    seq:
      - id: id
        type: u2
      - id: len_data
        type: u2
      - id: data
        size: len_data
KSY
mkdir -p "$tmp/kaitai/image"
cat > "$tmp/kaitai/image/png.ksy" <<'KSY'
meta:
  id: png
  endian: be
seq:
  - id: magic
    contents: [137, 80, 78, 71, 13, 10, 26, 10]
  - id: ihdr_len
    type: u4
    valid: 13
  - id: ihdr_type
    contents: "IHDR"
  - id: ihdr
    type: ihdr_chunk
  - id: ihdr_crc
    type: u4
  - id: chunks
    type: chunk
    repeat: until
    repeat-until: _.type == "IEND" or _io.eof
types:
  chunk:
    seq:
      - id: len
        type: u4
      - id: type_raw
        size: 4
        valid:
          expr: |
            ((_[0] >= 0x41 and _[0] <= 0x5a) or (_[0] >= 0x61 and _[0] <= 0x7a)) and
            ((_[1] >= 0x41 and _[1] <= 0x5a) or (_[1] >= 0x61 and _[1] <= 0x7a)) and
            ((_[2] >= 0x41 and _[2] <= 0x5a) or (_[2] >= 0x61 and _[2] <= 0x7a)) and
            ((_[3] >= 0x41 and _[3] <= 0x5a) or (_[3] >= 0x61 and _[3] <= 0x7a))
      - id: body
        size: len
      - id: crc
        type: u4
    instances:
      type:
        value: type_raw.to_s('ASCII')
  ihdr_chunk:
    seq:
      - id: width
        type: u4
        valid:
          min: 1
      - id: height
        type: u4
        valid:
          min: 1
      - id: bit_depth
        type: u1
        valid:
          any-of: [1, 2, 4, 8, 16]
      - id: color_type
        type: u1
        enum: color_type
        valid:
          in-enum: true
      - id: compression_method
        type: u1
        enum: compression_methods
        valid:
          in-enum: true
      - id: filter_method
        type: u1
        enum: filter_method
        valid:
          in-enum: true
      - id: interlace_method
        type: u1
        enum: interlace_method
        valid:
          in-enum: true
enums:
  color_type:
    0: greyscale
    2: truecolor
    3: indexed
    4: greyscale_alpha
    6: truecolor_alpha
  compression_methods:
    0: zlib
  filter_method:
    0: adaptive
  interlace_method:
    0: none
    1: adam7
KSY
cat > "$tmp/kaitai/game/doom_wad.ksy" <<'KSY'
meta:
  id: doom_wad
  endian: le
seq:
  - id: magic
    type: str
    size: 4
    encoding: ASCII
  - id: num_index_entries
    type: s4
  - id: index_offset
    type: s4
types:
  index_entry:
    seq:
      - id: offset
        type: s4
      - id: size
        type: s4
      - id: name
        type: str
        size: 8
        encoding: ASCII
        pad-right: 0
    instances:
      contents:
        io: _root._io
        pos: offset
        size: size
        type:
          switch-on: name
          cases:
            '"VERTEXES"': vertexes
            '"BLOCKMAP"': blockmap
  vertexes:
    seq:
      - id: entries
        type: vertex
        repeat: eos
  vertex:
    seq:
      - id: x
        type: s2
      - id: y
        type: s2
  blockmap:
    seq:
      - id: origin_x
        type: s2
      - id: origin_y
        type: s2
      - id: num_cols
        type: s2
      - id: num_rows
        type: s2
      - id: linedefs_in_block
        type: blocklist
        repeat: expr
        repeat-expr: num_cols * num_rows
    types:
      blocklist:
        seq:
          - id: offset
            type: u2
        instances:
          linedefs:
            pos: offset * 2
            type: s2
            repeat: until
            repeat-until: _ == -1
instances:
  index:
    pos: index_offset
    type: index_entry
    repeat: expr
    repeat-expr: num_index_entries
KSY
cat > "$tmp/kaitai/archive/zip.ksy" <<'KSY'
meta:
  id: zip
  endian: le
  bit-endian: le
seq:
  - id: sections
    type: pk_section
    repeat: eos
types:
  pk_section:
    seq:
      - id: magic
        contents: 'PK'
      - id: section_type
        type: u2
      - id: body
        type:
          switch-on: section_type
          cases:
            0x0201: central_dir_entry
            0x0403: local_file
            0x0605: end_of_central_dir
  local_file:
    seq:
      - id: header
        type: local_file_header
      - id: body
        size: header.len_body_compressed
  local_file_header:
    seq:
      - id: version
        type: u2
      - id: flags
        type: gp_flags
        size: 2
      - id: compression_method
        type: u2
        enum: compression
      - id: file_mod_time
        size: 4
        type: dos_datetime
      - id: crc32
        type: u4
      - id: len_body_compressed
        type: u4
      - id: len_body_uncompressed
        type: u4
      - id: len_file_name
        type: u2
      - id: len_extra
        type: u2
      - id: file_name
        type: str
        size: len_file_name
        encoding: UTF-8
      - id: extra
        size: len_extra
        type: extras
  gp_flags:
    seq:
      - id: file_encrypted
        type: b1
      - id: comp_options_raw
        type: b2
      - id: has_data_descriptor
        type: b1
      - id: reserved_1
        type: b1
      - id: comp_patched_data
        type: b1
      - id: strong_encrypt
        type: b1
      - id: reserved_2
        type: b4
      - id: lang_encoding
        type: b1
      - id: reserved_3
        type: b1
      - id: mask_header_values
        type: b1
      - id: reserved_4
        type: b2
    instances:
      deflated_mode:
        value: comp_options_raw
        if: _parent.compression_method == compression::deflated or _parent.compression_method == compression::enhanced_deflated
      imploded_dict_byte_size:
        value: 4096
        if: _parent.compression_method == compression::imploded
  central_dir_entry:
    seq:
      - id: version_made_by
        type: u2
      - id: version_needed_to_extract
        type: u2
      - id: flags
        type: u2
      - id: compression_method
        type: u2
        enum: compression
      - id: file_mod_time
        size: 4
        type: dos_datetime
      - id: crc32
        type: u4
      - id: len_body_compressed
        type: u4
      - id: len_body_uncompressed
        type: u4
      - id: len_file_name
        type: u2
      - id: len_extra
        type: u2
      - id: len_comment
        type: u2
      - id: disk_number_start
        type: u2
      - id: int_file_attr
        type: u2
      - id: ext_file_attr
        type: u4
      - id: ofs_local_header
        type: s4
      - id: file_name
        type: str
        size: len_file_name
        encoding: UTF-8
      - id: extra
        size: len_extra
        type: extras
      - id: comment
        type: str
        size: len_comment
        encoding: UTF-8
    instances:
      local_header:
        pos: ofs_local_header
        type: pk_section
  end_of_central_dir:
    seq:
      - id: disk_of_end_of_central_dir
        type: u2
      - id: disk_of_central_dir
        type: u2
      - id: num_central_dir_entries_on_disk
        type: u2
      - id: num_central_dir_entries_total
        type: u2
      - id: len_central_dir
        type: u4
      - id: ofs_central_dir
        type: u4
      - id: len_comment
        type: u2
      - id: comment
        type: str
        size: len_comment
        encoding: UTF-8
  extras:
    seq:
      - id: entries
        type: extra_field
        repeat: eos
  extra_field:
    seq:
      - id: code
        type: u2
      - id: len_body
        type: u2
      - id: body
        size: len_body
enums:
  compression:
    0: none
    6: imploded
    8: deflated
    9: enhanced_deflated
KSY
mkdir -p "$tmp/kaitai/common" "$tmp/kaitai/database"
cat > "$tmp/kaitai/common/dos_datetime.ksy" <<'KSY'
meta:
  id: dos_datetime
  bit-endian: le
seq:
  - id: time
    type: time
  - id: date
    type: date
types:
  time:
    seq:
      - id: second_div_2
        type: b5
        valid:
          max: 29
      - id: minute
        type: b6
        valid:
          max: 59
      - id: hour
        type: b5
        valid:
          max: 23
    instances:
      second:
        value: 2 * second_div_2
      padded_second:
        value: '(second <= 9 ? "0" : "") + second.to_s'
      padded_minute:
        value: '(minute <= 9 ? "0" : "") + minute.to_s'
      padded_hour:
        value: '(hour <= 9 ? "0" : "") + hour.to_s'
  date:
    seq:
      - id: day
        type: b5
        valid:
          min: 1
      - id: month
        type: b4
        valid:
          min: 1
          max: 12
      - id: year_minus_1980
        type: b7
    instances:
      year:
        value: 1980 + year_minus_1980
      padded_day:
        value: '(day <= 9 ? "0" : "") + day.to_s'
      padded_month:
        value: '(month <= 9 ? "0" : "") + month.to_s'
      padded_year:
        value: |
          (year <= 999 ? "0" +
            (year <= 99 ? "0" +
              (year <= 9 ? "0" : "")
            : "")
          : "") + year.to_s
KSY
cat > "$tmp/kaitai/filesystem/vfat.ksy" <<'KSY'
meta:
  id: vfat
  imports:
    - /common/dos_datetime
  endian: le
  bit-endian: le
seq:
  - id: boot_sector
    type: boot_sector
instances:
  fats:
    pos: boot_sector.pos_fats
    size: boot_sector.size_fat
    repeat: expr
    repeat-expr: boot_sector.bpb.num_fats
  root_dir:
    pos: boot_sector.pos_root_dir
    size: boot_sector.size_root_dir
    type: root_directory
types:
  boot_sector:
    seq:
      - id: jmp_instruction
        size: 3
      - id: oem_name
        type: str
        encoding: ASCII
        pad-right: 0x20
        size: 8
      - id: bpb
        type: bios_param_block
      - id: ebpb_fat16
        type: ext_bios_param_block_fat16
        if: not is_fat32
      - id: ebpb_fat32
        type: ext_bios_param_block_fat32
        if: is_fat32
    instances:
      is_fat32:
        value: bpb.max_root_dir_rec == 0
      pos_fats:
        value: bpb.bytes_per_ls * bpb.num_reserved_ls
      ls_per_fat:
        value: 'is_fat32 ? ebpb_fat32.ls_per_fat : bpb.ls_per_fat'
      size_fat:
        value: bpb.bytes_per_ls * ls_per_fat
      pos_root_dir:
        value: bpb.bytes_per_ls * (bpb.num_reserved_ls + ls_per_fat * bpb.num_fats)
      ls_per_root_dir:
        value: (bpb.max_root_dir_rec * 32 + bpb.bytes_per_ls - 1) / bpb.bytes_per_ls
      size_root_dir:
        value: ls_per_root_dir * bpb.bytes_per_ls
  bios_param_block:
    seq:
      - id: bytes_per_ls
        type: u2
      - id: ls_per_clus
        type: u1
      - id: num_reserved_ls
        type: u2
      - id: num_fats
        type: u1
      - id: max_root_dir_rec
        type: u2
      - id: total_ls_2
        type: u2
      - id: media_code
        type: u1
      - id: ls_per_fat
        type: u2
      - id: ps_per_track
        type: u2
      - id: num_heads
        type: u2
      - id: num_hidden_sectors
        type: u4
      - id: total_ls_4
        type: u4
  ext_bios_param_block_fat16:
    seq:
      - id: phys_drive_num
        type: u1
      - id: reserved1
        type: u1
      - id: ext_boot_sign
        type: u1
      - id: volume_id
        size: 4
      - id: partition_volume_label
        size: 11
        type: str
        encoding: ASCII
        pad-right: 0x20
      - id: fs_type_str
        size: 8
        type: str
        encoding: ASCII
        pad-right: 0x20
  ext_bios_param_block_fat32:
    seq:
      - id: ls_per_fat
        type: u4
      - id: has_active_fat
        type: b1
      - id: reserved1
        type: b3
      - id: active_fat_id
        type: b4
      - id: reserved2
        contents: [0]
      - id: fat_version
        type: u2
      - id: root_dir_start_clus
        type: u4
      - id: tail
        size: 40
  root_directory:
    seq:
      - id: records
        type: root_directory_rec
        repeat: expr
        repeat-expr: _root.boot_sector.bpb.max_root_dir_rec
  root_directory_rec:
    seq:
      - id: file_name
        size: 11
      - id: attrs
        size: 1
        type: attr_flags
      - id: reserved
        size: 10
      - id: last_write_time
        size: 4
        type: dos_datetime
      - id: start_clus
        type: u2
      - id: file_size
        type: u4
    types:
      attr_flags:
        seq:
          - id: read_only
            type: b1
          - id: hidden
            type: b1
          - id: system
            type: b1
          - id: volume_id
            type: b1
          - id: is_directory
            type: b1
          - id: archive
            type: b1
          - id: reserved
            type: b2
        instances:
          long_name:
            value: |
              read_only
              and hidden
              and system
              and volume_id
KSY
cat > "$tmp/kaitai/common/vlq_base128_be.ksy" <<'KSY'
meta:
  id: vlq_base128_be
  bit-endian: be
seq:
  - id: groups
    type: group
    repeat: until
    repeat-until: not _.has_next
types:
  group:
    seq:
      - id: has_next
        type: b1
      - id: value
        type: b7
instances:
  last:
    value: groups.size - 1
  value:
    value: |
      (groups[last].value
      + (last >= 1 ? (groups[last - 1].value << 7) : 0)
      + (last >= 2 ? (groups[last - 2].value << 14) : 0)).as<u8>
KSY
cat > "$tmp/kaitai/database/sqlite3.ksy" <<'KSY'
meta:
  id: sqlite3
  imports:
    - /common/vlq_base128_be
  endian: be
seq:
  - id: magic
    contents: ["SQLite format 3", 0]
  - id: len_page_mod
    type: u2
  - id: write_version
    type: u1
  - id: read_version
    type: u1
  - id: reserved_space
    type: u1
  - id: max_payload_frac
    type: u1
  - id: min_payload_frac
    type: u1
  - id: leaf_payload_frac
    type: u1
  - id: file_change_counter
    type: u4
  - id: num_pages
    type: u4
  - id: first_freelist_trunk_page
    type: u4
  - id: num_freelist_pages
    type: u4
  - id: schema_cookie
    type: u4
  - id: schema_format
    type: u4
  - id: def_page_cache_size
    type: u4
  - id: largest_root_page
    type: u4
  - id: text_encoding
    type: u4
  - id: user_version
    type: u4
  - id: is_incremental_vacuum
    type: u4
  - id: application_id
    type: u4
  - id: reserved
    size: 20
  - id: version_valid_for
    type: u4
  - id: sqlite_version_number
    type: u4
  - id: root_page
    type: btree_page
instances:
  len_page:
    value: 'len_page_mod == 1 ? 0x10000 : len_page_mod'
types:
  btree_page:
    seq:
      - id: page_type
        type: u1
      - id: first_freeblock
        type: u2
      - id: num_cells
        type: u2
      - id: ofs_cells
        type: u2
      - id: num_frag_free_bytes
        type: u1
      - id: right_ptr
        type: u4
        if: page_type == 2 or page_type == 5
      - id: cells
        type: ref_cell
        repeat: expr
        repeat-expr: num_cells
  ref_cell:
    seq:
      - id: ofs_body
        type: u2
    instances:
      body:
        pos: ofs_body
        type:
          switch-on: _parent.page_type
          cases:
            0x0d: cell_table_leaf
  cell_table_leaf:
    seq:
      - id: len_payload
        type: vlq_base128_be
      - id: row_id
        type: vlq_base128_be
      - id: payload
        size: len_payload.value
        type: cell_payload
  cell_payload:
    seq:
      - id: len_header_and_len
        type: vlq_base128_be
      - id: column_serials
        size: len_header_and_len.value - 1
        type: serials
      - id: column_contents
        repeat: expr
        repeat-expr: column_serials.entries.size
        type: column_content(column_serials.entries[_index])
  serials:
    seq:
      - id: entries
        type: serial
        repeat: eos
  serial:
    seq:
      - id: code
        type: vlq_base128_be
    instances:
      is_blob:
        value: 'code.value >= 12 and (code.value % 2 == 0)'
      is_string:
        value: 'code.value >= 13 and (code.value % 2 == 1)'
      len_content:
        value: (code.value - 12) / 2
        if: code.value >= 12
  column_content:
    params:
      - id: serial_type
        type: serial
    seq:
      - id: as_int
        type:
          switch-on: serial_type.code.value
          cases:
            1: u1
            2: u2
            3: b24
            4: u4
            5: b48
            6: u8
        if: serial_type.code.value >= 1 and serial_type.code.value <= 6
      - id: as_float
        type: f8
        if: serial_type.code.value == 7
      - id: as_blob
        size: serial_type.len_content
        if: serial_type.is_blob
      - id: as_str
        type: str
        size: serial_type.len_content
        encoding: UTF-8
KSY
cat > "$tmp/kaitai/filesystem/ext2.ksy" <<'KSY'
meta:
  id: ext2
  endian: le
instances:
  bg1:
    pos: 1024
    type: block_group
  root_dir:
    value: bg1.block_groups[0].inodes[1].as_dir
types:
  block_group:
    seq:
      - id: super_block
        type: super_block_struct
        size: 1024
      - id: block_groups
        type: bgd
        repeat: expr
        repeat-expr: super_block.block_group_count
  super_block_struct:
    seq:
      - id: inodes_count
        type: u4
      - id: blocks_count
        type: u4
      - id: r_blocks_count
        type: u4
      - id: free_blocks_count
        type: u4
      - id: free_inodes_count
        type: u4
      - id: first_data_block
        type: u4
      - id: log_block_size
        type: u4
      - id: log_frag_size
        type: u4
      - id: blocks_per_group
        type: u4
      - id: frags_per_group
        type: u4
      - id: inodes_per_group
        type: u4
      - id: mtime
        type: u4
      - id: wtime
        type: u4
      - id: mnt_count
        type: u2
      - id: max_mnt_count
        type: u2
      - id: magic
        contents: [0x53, 0xef]
      - id: state
        type: u2
      - id: errors
        type: u2
      - id: minor_rev_level
        type: u2
      - id: lastcheck
        type: u4
      - id: checkinterval
        type: u4
      - id: creator_os
        type: u4
      - id: rev_level
        type: u4
      - id: def_resuid
        type: u2
      - id: def_resgid
        type: u2
      - id: first_ino
        type: u4
      - id: inode_size
        type: u2
      - id: block_group_nr
        type: u2
    instances:
      block_size:
        value: 1024 << log_block_size
      block_group_count:
        value: blocks_count / blocks_per_group
  bgd:
    seq:
      - id: block_bitmap_block
        type: u4
      - id: inode_bitmap_block
        type: u4
      - id: inode_table_block
        type: u4
      - id: free_blocks_count
        type: u2
      - id: free_inodes_count
        type: u2
      - id: used_dirs_count
        type: u2
      - id: pad_reserved
        size: 14
    instances:
      inodes:
        pos: inode_table_block * _root.bg1.super_block.block_size
        type: inode
        repeat: expr
        repeat-expr: _root.bg1.super_block.inodes_per_group
  inode:
    seq:
      - id: mode
        type: u2
      - id: uid
        type: u2
      - id: size
        type: u4
      - id: atime
        type: u4
      - id: ctime
        type: u4
      - id: mtime
        type: u4
      - id: dtime
        type: u4
      - id: gid
        type: u2
      - id: links_count
        type: u2
      - id: blocks
        type: u4
      - id: flags
        type: u4
      - id: osd1
        type: u4
      - id: block
        type: block_ptr
        repeat: expr
        repeat-expr: 15
      - id: generation
        type: u4
      - id: file_acl
        type: u4
      - id: dir_acl
        type: u4
      - id: faddr
        type: u4
      - id: osd2
        size: 12
    instances:
      as_dir:
        io: block[0].body._io
        pos: 0
        type: dir
  block_ptr:
    seq:
      - id: ptr
        type: u4
    instances:
      body:
        pos: ptr * _root.bg1.super_block.block_size
        size: _root.bg1.super_block.block_size
        type: raw_block
  raw_block:
    seq:
      - id: body
        size: _root.bg1.super_block.block_size
  dir:
    seq:
      - id: entries
        type: dir_entry
        repeat: eos
  dir_entry:
    seq:
      - id: inode_ptr
        type: u4
      - id: rec_len
        type: u2
      - id: name_len
        type: u1
      - id: file_type
        type: u1
      - id: name
        size: name_len
        type: str
        encoding: UTF-8
      - id: padding
        size: rec_len - name_len - 8
KSY

cat > "$tmp/kaitai/filesystem/iso9660.ksy" <<'KSY'
meta:
  id: iso9660
types:
  vol_desc:
    seq:
      - id: type
        type: u1
      - id: magic
        contents: "CD001"
      - id: version
        type: u1
      - id: vol_desc_primary
        type: vol_desc_primary
        if: type == 1
  vol_desc_primary:
    seq:
      - id: unused1
        contents: [0]
      - id: system_id
        type: str
        size: 32
        encoding: UTF-8
      - id: volume_id
        type: str
        size: 32
        encoding: UTF-8
      - id: unused2
        contents: [0, 0, 0, 0, 0, 0, 0, 0]
      - id: vol_space_size
        type: u4bi
      - id: logical_block_size
        type: u2bi
      - id: lba_path_table_le
        type: u4le
    instances:
      path_table:
        pos: lba_path_table_le * _root.sector_size
        size: 10
        type: path_table_le
  path_table_le:
    seq:
      - id: entries
        type: path_table_entry_le
        repeat: eos
  path_table_entry_le:
    seq:
      - id: len_dir_name
        type: u1
      - id: len_ext_attr_rec
        type: u1
      - id: lba_extent
        type: u4le
      - id: parent_dir_idx
        type: u2le
      - id: dir_name
        type: str
        encoding: UTF-8
        size: len_dir_name
      - id: padding
        type: u1
        if: len_dir_name % 2 == 1
  u2bi:
    seq:
      - id: le
        type: u2le
      - id: be
        type: u2be
  u4bi:
    seq:
      - id: le
        type: u4le
      - id: be
        type: u4be
instances:
  sector_size:
    value: 2048
  primary_vol_desc:
    pos: 0x010 * sector_size
    type: vol_desc
KSY

mkdir -p "$tmp/kaitai/misc"
cat > "$tmp/kaitai/misc/poison_auto.ksy" <<'KSY'
meta:
  id: poison_auto
  endian: le
seq:
  - id: magic
    contents: "BAD!!"
  - id: values
    type: u1
    repeat: expr
    repeat-expr: 1 / 0
KSY

mkdir -p "$tmp/kaitai/misc"
cat > "$tmp/kaitai/misc/blank_reserved.ksy" <<'KSY'
meta:
  id: blank_reserved
seq:
  - id: reserved
    contents: [0, 0, 0, 0, 0, 0, 0, 0]
  - id: payload
    size-eos: true
KSY
cat > "$tmp/kaitai/misc/erased_reserved.ksy" <<'KSY'
meta:
  id: erased_reserved
seq:
  - id: reserved
    contents: [255, 255, 255, 255, 255, 255, 255, 255]
  - id: payload
    size-eos: true
KSY
cat > "$tmp/kaitai/misc/space_reserved.ksy" <<'KSY'
meta:
  id: space_reserved
seq:
  - id: reserved
    contents: "        "
  - id: payload
    size-eos: true
KSY
export CLARITY_KSY_ROOT="$tmp/kaitai"

python3 - <<'PY' > "$tmp/plain.bin"
import sys
sys.stdout.buffer.write((b"The quick brown fox jumps over the lazy dog.\n" * 10000) + bytes(range(256)) * 20)
PY
: > "$tmp/empty.bin"
printf '\000\377\020\200key\000tail' > "$tmp/key.bin"

# --- Garble mechanics: every transform family must obey the same container contract. ---

./garble -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/xor.grb"
./garble -d -k 'BlueVelvet' "$tmp/xor.grb" "$tmp/xor.out"
cmp "$tmp/plain.bin" "$tmp/xor.out"

./garble -t subst -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/subst.grb"
./garble -d -k 'BlueVelvet' "$tmp/subst.grb" "$tmp/subst.out"
cmp "$tmp/plain.bin" "$tmp/subst.out"

./garble -t shuffle -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/shuffle.grb"
./garble -d -k 'BlueVelvet' "$tmp/shuffle.grb" "$tmp/shuffle.out"
cmp "$tmp/plain.bin" "$tmp/shuffle.out"

# Empty input still produces a valid container and decodes to empty for both transforms.
for t in xor subst shuffle; do
    ./garble -t "$t" -k x "$tmp/empty.bin" "$tmp/empty-$t.grb"
    ./garble -d -k x "$tmp/empty-$t.grb" "$tmp/empty-$t.out"
    cmp "$tmp/empty.bin" "$tmp/empty-$t.out"
    [ "$(wc -c < "$tmp/empty-$t.grb")" -eq 32 ]
done

# Binary key file, including NUL and high bytes.
for t in xor subst shuffle; do
    ./garble -t "$t" -K "$tmp/key.bin" "$tmp/plain.bin" "$tmp/binary-$t.grb"
    ./garble -d -K "$tmp/key.bin" "$tmp/binary-$t.grb" "$tmp/binary-$t.out"
    cmp "$tmp/plain.bin" "$tmp/binary-$t.out"
done

# Pure stdin/stdout operation in both directions.
for t in xor subst shuffle; do
    cat "$tmp/plain.bin" | ./garble -t "$t" -k PipeKey - - | ./garble -d -k PipeKey - - > "$tmp/pipe-$t.out"
    cmp "$tmp/plain.bin" "$tmp/pipe-$t.out"
done

# Refuse destructive same-file output, including hard-link aliases.
cp "$tmp/plain.bin" "$tmp/same.bin"
if ./garble -k x "$tmp/same.bin" "$tmp/same.bin" >/dev/null 2>&1; then
    echo "FAIL: identical input/output path accepted" >&2
    exit 1
fi
cmp "$tmp/plain.bin" "$tmp/same.bin"
ln "$tmp/same.bin" "$tmp/same-link.bin"
if ./garble -t subst -k x "$tmp/same.bin" "$tmp/same-link.bin" >/dev/null 2>&1; then
    echo "FAIL: hard-link input/output alias accepted" >&2
    exit 1
fi
cmp "$tmp/plain.bin" "$tmp/same.bin"

# Wrong keys and modified payloads must fail integrity for both transforms.
for t in xor subst shuffle; do
    src="$tmp/$t.grb"
    if ./garble -d -k WrongKey "$src" "$tmp/wrong-$t.bin" >/dev/null 2>&1; then
        echo "FAIL: $t accepted wrong key" >&2
        exit 1
    fi
    cp "$src" "$tmp/tampered-$t.grb"
    python3 - "$tmp/tampered-$t.grb" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
b = bytearray(p.read_bytes())
b[32] ^= 0x80
p.write_bytes(b)
PY
    if ./garble -d -k BlueVelvet "$tmp/tampered-$t.grb" "$tmp/tampered-$t.out" >/dev/null 2>&1; then
        echo "FAIL: $t accepted tampered payload" >&2
        exit 1
    fi
done

# Header remains byte-exact; only transform ID differs.
python3 - "$tmp/xor.grb" "$tmp/subst.grb" "$tmp/shuffle.grb" <<'PY'
from pathlib import Path
import sys
for path, transform_id in ((sys.argv[1], 1), (sys.argv[2], 2), (sys.argv[3], 3)):
    b = Path(path).read_bytes()[:16]
    assert b[:8] == b'GRBLv1\r\n'
    assert b[8] == 1 and b[9] == transform_id and b[10:12] == b'\0\0'
    assert int.from_bytes(b[12:16], 'little') == 16
PY
if ./garble -d -t xor -k BlueVelvet "$tmp/xor.grb" "$tmp/nope" >/dev/null 2>&1; then
    echo "FAIL: decode accepted encode-only -t" >&2
    exit 1
fi
if ./garble -t nope -k x "$tmp/plain.bin" "$tmp/nope" >/dev/null 2>&1; then
    echo "FAIL: unknown transform accepted" >&2
    exit 1
fi

# Small analysis specimens keep Clarity CLI tests dense without making each statistical
# pass chew through the larger streaming fixture above.
python3 - <<'PY2' > "$tmp/probe-plain.bin"
import sys
sys.stdout.buffer.write((b"The quick brown fox jumps over the lazy dog.\n" * 200) + bytes(4096) + bytes(range(256)) * 4)
PY2
./garble -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-xor.grb"
./garble -t subst -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-subst.grb"
./garble -t shuffle -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb"

# --- Clarity's instruments: prove the measuring sticks before using them. ---

python3 - <<'PY'
import binascii
import math
import struct
import zlib
import clarity

checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

check("empty entropy", clarity.entropy(b"") == 0.0)
check("uniform entropy", math.isclose(clarity.entropy(bytes(range(256)) * 4), 8.0, abs_tol=1e-12))
check("exact lag coincidence", clarity.coincidence(b"abcabcabc", 3) == 1.0)
check("nonmatching lag coincidence", clarity.coincidence(b"abcdef", 1) == 0.0)
check("full hamming distance", clarity.hamming_ratio(b"\x00", b"\xff") == 1.0)
check("zero hamming distance", clarity.hamming_ratio(b"same", b"same") == 0.0)
check("exact period", clarity.smallest_period_exact(b"abcabcab", 8) == 3)
check("no exact period", clarity.smallest_period_exact(b"abcdef", 3) is None)
check("constant serial correlation", clarity.serial_correlation(b"\x07" * 100) == 0.0)
check("printable annotation", clarity.byte_annotation(0x45) == "ASCII 'E'")
check("control annotation", clarity.byte_annotation(0x0a) == "LF")
check("unnamed byte annotation", clarity.byte_annotation(0x80) is None)
periodic = (b"abcdefg" * 700)[:4096]
claim = clarity.periodicity_claim(periodic, 128)
check("period claim", claim is not None and claim["period"] == 7)
check("fill structural character", clarity.structural_character(b"\xaa" * 1024)["kind"] == "fill")
check("ASCII structural character", clarity.structural_character((b"hello world\n" * 100))["kind"] == "ascii_compatible")
check("nontext structural character", clarity.structural_character(bytes(range(32)) * 32)["kind"] == "other")

loaded = clarity.load_ksy("filesystem/mbr_partition_table.ksy")
check("external MBR KSY loaded", loaded is not None and loaded[0]["meta"]["id"] == "mbr_partition_table")
check("KSY static MBR extent", clarity.ksy_static_size(loaded[0]) == 512)

# MBR geometry: one valid partition plus three empty records. The view is allowed
# to survive a missing signature, but the identity claim is not.
mbr = bytearray(512)
p = 0x1be
mbr[p] = 0x80
mbr[p + 4] = 0x83
mbr[p + 8:p + 12] = (2048).to_bytes(4, "little")
mbr[p + 12:p + 16] = (409600).to_bytes(4, "little")
mbr[510:512] = b"\x55\xaa"
view = clarity.mbr_view_at(bytes(mbr), 0)
check("MBR strong view", view is not None and view["strong_identity"] and view["checks_passed"] == 10)
parsed = clarity.parse_ksy_structure(bytes(mbr), loaded[0], root_path="mbr")
by_path = {a["path"]: a for a in parsed["annotations"]}
check("KSY nested type projection", by_path["mbr.partitions[0].chs_start"]["end"] - by_path["mbr.partitions[0].chs_start"]["start"] == 3)
check("KSY nested subfield projection", by_path["mbr.partitions[0].chs_start.head"]["kind"] == "subfield")
check("KSY literal constraint", next(c for c in parsed["constraints"] if c["path"] == "mbr.boot_signature")["passed"])
check("MBR exact partition-table span", any(
    a["path"] == "mbr.partitions" and a["start"] == 0x1be and a["end"] == 0x1fe
    for a in view["annotations"]
))
check("MBR identity claim", len(clarity.mbr_identity_claims(bytes(mbr))) == 1)
mbr[510:512] = b"\0\0"
partial = clarity.mbr_view_at(bytes(mbr), 0)
check("MBR partial view survives damage", partial is not None and not partial["strong_identity"] and partial["checks_passed"] == 9)
check("MBR damaged identity abstains", not clarity.mbr_identity_claims(bytes(mbr)))

# A positioned viewport must not re-label an arbitrary aligned sector as an MBR.
window_views = clarity.analysis_result(bytes(mbr), 16, 0x99cbdba00, windowed=True)[3]
check("windowed MBR location discipline", not any(v.get("kind") == "mbr_partition_table" for v in window_views))

# ``contents`` is not synonymous with magic.  Long reserved/padding literals
# must never make blank or erased media look like a discovered object.
blank_views = clarity.auto_ksy_views(bytes(4096), 0)
erased_views = clarity.auto_ksy_views(bytes([0xff]) * 4096, 0)
space_views = clarity.auto_ksy_views(b" " * 4096, 0)
check("auto KSY blank media abstains", not blank_views)
check("auto KSY erased media abstains", not erased_views)
check("auto KSY space padding abstains", not space_views)
check("auto KSY rejects short generic magic", not clarity._auto_anchor_is_discriminating(b"PACK"))
check("auto KSY accepts GPT-strength magic", clarity._auto_anchor_is_discriminating(b"EFI PART"))

# Strong static KSY literals nominate other structures automatically.  GPT is an
# instance-only root whose defining signature lives at LBA1; auto projection must
# select the primary branch without pretending the viewport end is the backup LBA.
gpt = bytearray(4096)
h = 512
gpt[h:h+8] = b"EFI PART"
gpt[h+8:h+12] = (0x00010000).to_bytes(4, "little")
gpt[h+12:h+16] = (92).to_bytes(4, "little")
gpt[h+24:h+32] = (1).to_bytes(8, "little")
gpt[h+32:h+40] = (0x100000).to_bytes(8, "little")
gpt[h+40:h+48] = (34).to_bytes(8, "little")
gpt[h+48:h+56] = (0x0fffff).to_bytes(8, "little")
gpt[h+72:h+80] = (2).to_bytes(8, "little")
gpt[h+80:h+84] = (2).to_bytes(4, "little")
gpt[h+84:h+88] = (128).to_bytes(4, "little")
e = 1024
gpt[e:e+16] = bytes(range(1, 17))
gpt[e+16:e+32] = bytes(range(17, 33))
gpt[e+32:e+40] = (2048).to_bytes(8, "little")
gpt[e+40:e+48] = (4095).to_bytes(8, "little")
name = "data".encode("utf-16le")
gpt[e+56:e+56+len(name)] = name
e2 = e + 128
gpt[e2:e2+16] = bytes(range(33, 49))
gpt[e2+16:e2+32] = bytes(range(49, 65))
gpt[e2+32:e2+40] = (4096).to_bytes(8, "little")
gpt[e2+40:e2+48] = (8191).to_bytes(8, "little")
name2 = "more".encode("utf-16le")
gpt[e2+56:e2+56+len(name2)] = name2
gpt_views = clarity.auto_ksy_views(bytes(gpt), 0)
gpt_view = next((v for v in gpt_views if v.get("ksy_id") == "gpt_partition_table"), None)
check("auto KSY GPT candidate", gpt_view is not None and gpt_view["offset"] == 0 and gpt_view["strong_identity"])
check("auto KSY GPT primary geometry", gpt_view is not None and any(
    a.get("path") == "gpt_partition_table.primary.signature" and a.get("start") == 512 and a.get("end") == 520
    for a in gpt_view["annotations"]
))
check("auto KSY GPT repeated sized entries", gpt_view is not None and any(
    a.get("path") == "gpt_partition_table.primary.entries[1].first_lba" and a.get("start") == e2 + 32
    for a in gpt_view["annotations"]
))
check("auto KSY GPT excludes fake backup", gpt_view is not None and not any(
    str(a.get("path", "")).startswith("gpt_partition_table.backup") for a in gpt_view["annotations"]
))
check("MBR identity helper ignores generic KSY views", clarity.mbr_identity_claim_from_view({
    "kind": "ksy_structure", "strong_identity": True
}) is None)
# Exercise the public analysis path used by FatPix, not only the direct KSY helper.
# This catches accidental assumptions that every structural view is an MBR.
gpt_analysis_views = clarity.analysis_result(bytes(gpt), 16, 0, windowed=True)[3]
check("windowed analysis carries automatic GPT view", any(
    v.get("kind") == "ksy_structure" and v.get("ksy_id") == "gpt_partition_table"
    for v in gpt_analysis_views
))

# The same generic KSY machinery now handles two unrelated real corpus shapes
# without a Quake- or cpio-specific parser in clarity.py.
pak_loaded = clarity.load_ksy("game/quake_pak.ksy")
check("external Quake PAK KSY loaded", pak_loaded is not None and pak_loaded[0]["meta"]["id"] == "quake_pak")
pak_body0 = b"HELLO"
pak_body1 = b"WORLD!!"
pak_index_offset = 12 + len(pak_body0) + len(pak_body1)
pak_entries = b""
for name, ofs, body in (
    ("maps/e1m1.bsp", 12, pak_body0),
    ("gfx/palette.lmp", 12 + len(pak_body0), pak_body1),
):
    pak_entries += name.encode("utf-8").ljust(56, b"\0") + struct.pack("<II", ofs, len(body))
pak = b"PACK" + struct.pack("<II", pak_index_offset, len(pak_entries)) + pak_body0 + pak_body1 + pak_entries
pak_parsed = clarity.parse_ksy_structure(pak, pak_loaded[0])
check("PAK out-of-line index extent", pak_parsed["extent"] == len(pak))
check("PAK repeat-eos entries", len(pak_parsed["values"]["quake_pak.index.entries"]) == 2)
check("PAK fixed string decode", pak_parsed["values"]["quake_pak.index.entries[0].name"] == "maps/e1m1.bsp")
pak_ann = {a["path"]: a for a in pak_parsed["annotations"]}
check("PAK root-io body instance", (
    pak_ann["quake_pak.index.entries[1].body"]["start"],
    pak_ann["quake_pak.index.entries[1].body"]["end"],
) == (12 + len(pak_body0), 12 + len(pak_body0) + len(pak_body1)))

cpio_loaded = clarity.load_ksy("archive/cpio_old_le.ksy")
check("external cpio KSY loaded", cpio_loaded is not None and cpio_loaded[0]["meta"]["id"] == "cpio_old_le")
def cpio_u2(value):
    return struct.pack("<H", value)
def cpio_u4_split(value):
    return cpio_u2((value >> 16) & 0xffff) + cpio_u2(value & 0xffff)
def cpio_member(name, body, inode):
    name_size = len(name) + 1
    header = (
        b"\xc7\x71"
        + cpio_u2(0) + cpio_u2(inode) + cpio_u2(0o100644)
        + cpio_u2(0) + cpio_u2(0) + cpio_u2(1) + cpio_u2(0)
        + cpio_u4_split(1234) + cpio_u2(name_size) + cpio_u4_split(len(body))
    )
    out = header + name + b"\0"
    if name_size % 2:
        out += b"\0"
    out += body
    if len(body) % 2:
        out += b"\0"
    return out
cpio = cpio_member(b"hi", b"abc", 1) + cpio_member(b"TRAILER!!!", b"", 2) + b"\0" * 8
cpio_parsed = clarity.parse_ksy_structure(cpio, cpio_loaded[0])
check("cpio repeat-eos members", len(cpio_parsed["values"]["cpio_old_le.files"]) == 2)
check("cpio dynamic size + computed instance", cpio_parsed["values"]["cpio_old_le.files[0].header.file_size.value"] == 3)
check("cpio conditional size-eos trailer", cpio_parsed["values"]["cpio_old_le.files[1].end_of_file_padding"] == b"\0" * 8)
check("generic explicit KSY projection", clarity.project_ksy(pak, "game/quake_pak.ksy")["ksy_id"] == "quake_pak")

gzip_loaded = clarity.load_ksy("archive/gzip.ksy")
check("external gzip KSY loaded", gzip_loaded is not None and gzip_loaded[0]["meta"]["id"] == "gzip")
gzip_plain = b"hello hello hello\n"
compressor = zlib.compressobj(level=6, wbits=-15)
gzip_body = compressor.compress(gzip_plain) + compressor.flush()
gzip_data = (
    b"\x1f\x8b" + bytes([8, 0x08]) + struct.pack("<I", 123456) + bytes([0, 3])
    + b"hello.txt\0" + gzip_body
    + struct.pack("<II", binascii.crc32(gzip_plain) & 0xffffffff, len(gzip_plain))
)
gzip_parsed = clarity.parse_ksy_structure(gzip_data, gzip_loaded[0])
check("gzip bit-field condition", gzip_parsed["values"]["gzip.flags.has_name"] == 1)
check("gzip terminator field", gzip_parsed["values"]["gzip.name"] == b"hello.txt")
check("gzip enum switch", gzip_parsed["values"]["gzip.extra_flags.compression_strength"] == 0)
check("gzip _io dynamic body extent", gzip_parsed["values"]["gzip.len_uncompressed"] == len(gzip_plain) and gzip_parsed["extent"] == len(gzip_data))

png_loaded = clarity.load_ksy("image/png.ksy")
check("external PNG KSY loaded", png_loaded is not None and png_loaded[0]["meta"]["id"] == "png")
def png_chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xffffffff)
png_ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
png_data = (
    b"\x89PNG\r\n\x1a\n"
    + png_chunk(b"IHDR", png_ihdr)
    + png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    + png_chunk(b"IEND", b"")
)
png_parsed = clarity.parse_ksy_structure(png_data, png_loaded[0])
check("PNG repeat-until chunks", len(png_parsed["values"]["png.chunks"]) == 2)
check("PNG computed chunk type string", png_parsed["values"]["png.chunks[0].type"] == "IDAT" and png_parsed["values"]["png.chunks[1].type"] == "IEND")
check("PNG validity constraints pass", len(png_parsed["constraints"]) >= 10 and all(row["passed"] for row in png_parsed["constraints"]))
png_bad = bytearray(png_data)
png_bad[11] = 12  # IHDR length says 12 instead of the required 13; shape can still be projected.
png_bad_parsed = clarity.parse_ksy_structure(bytes(png_bad), png_loaded[0])
check("PNG failed valid is evidence not parser death", any(row["kind"] == "valid" and row["path"] == "png.ihdr_len" and not row["passed"] for row in png_bad_parsed["constraints"]))

wad_loaded = clarity.load_ksy("game/doom_wad.ksy")
check("external Doom WAD KSY loaded", wad_loaded is not None and wad_loaded[0]["meta"]["id"] == "doom_wad")
vertex_body = struct.pack("<hhhh", 10, 20, -30, 40)
blockmap_body = struct.pack("<hhhhHhhh", 0, 0, 1, 1, 5, 0, 7, -1)
vertex_ofs = 12
blockmap_ofs = vertex_ofs + len(vertex_body)
wad_index_ofs = blockmap_ofs + len(blockmap_body)
wad_index = (
    struct.pack("<ii8s", vertex_ofs, len(vertex_body), b"VERTEXES")
    + struct.pack("<ii8s", blockmap_ofs, len(blockmap_body), b"BLOCKMAP")
)
wad_data = b"PWAD" + struct.pack("<ii", 2, wad_index_ofs) + vertex_body + blockmap_body + wad_index
wad_parsed = clarity.parse_ksy_structure(wad_data, wad_loaded[0])
check("WAD repeated out-of-line index instance", len(wad_parsed["values"]["doom_wad.index"]) == 2)
check("WAD switched VERTEXES payload", len(wad_parsed["values"]["doom_wad.index[0].contents.entries"]) == 2 and wad_parsed["values"]["doom_wad.index[0].contents.entries[1].x"] == -30)
check("WAD nested local type + repeat-until instance", wad_parsed["values"]["doom_wad.index[1].contents.linedefs_in_block[0].linedefs"] == [0, 7, -1])

zip_loaded = clarity.load_ksy("archive/zip.ksy")
check("external ZIP KSY loaded", zip_loaded is not None and zip_loaded[0]["meta"]["id"] == "zip")
zip_name = b"a.txt"
zip_body = b"HELLO"
zip_crc = binascii.crc32(zip_body) & 0xffffffff
zip_local = (
    b"PK" + struct.pack("<H", 0x0403)
    + struct.pack("<HHH", 20, 0, 0) + b"\0\0\0\0"
    + struct.pack("<IIIHH", zip_crc, len(zip_body), len(zip_body), len(zip_name), 0)
    + zip_name + zip_body
)
zip_central_ofs = len(zip_local)
zip_central_body = (
    struct.pack("<HHHH", 20, 20, 0, 0) + b"\0\0\0\0"
    + struct.pack("<IIIHHHHHII", zip_crc, len(zip_body), len(zip_body), len(zip_name), 0, 0, 0, 0, 0, 0)
    + zip_name
)
zip_central = b"PK" + struct.pack("<H", 0x0201) + zip_central_body
zip_eocd = b"PK" + struct.pack("<H", 0x0605) + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(zip_central), zip_central_ofs, 0)
zip_data = zip_local + zip_central + zip_eocd
zip_parsed = clarity.parse_ksy_structure(zip_data, zip_loaded[0])
check("ZIP repeated section stream", [zip_parsed["values"][f"zip.sections[{i}].section_type"] for i in range(3)] == [0x0403, 0x0201, 0x0605])
check("ZIP local-file structure", zip_parsed["values"]["zip.sections[0].body.header.file_name"] == "a.txt" and zip_parsed["values"]["zip.sections[0].body.body"] == zip_body)
check("ZIP lazy parent-dependent instance", zip_parsed["values"]["zip.sections[1].body.local_header.body.header.file_name"] == "a.txt")

param_doc = clarity.parse_ksy_yaml("""
meta:
  id: param_probe
seq:
  - id: pair
    type: pair(true)
types:
  pair:
    params:
      - id: has_b
        type: bool
    seq:
      - id: a
        type: u1
      - id: b
        type: u1
        if: has_b
""")
param_parsed = clarity.parse_ksy_structure(b"\x11\x22", param_doc)
check("KSY parameterized nested type", param_parsed["values"]["param_probe.pair.b"] == 0x22)
enum_doc = clarity.parse_ksy_yaml("""
meta:
  id: enum_probe
seq:
  - id: mode
    type: u1
    enum: mode
  - id: payload
    type: u1
    if: mode == mode::yes
instances:
  chosen:
    value: 'mode == mode::yes ? 7 : 9'
enums:
  mode:
    0: no
    1: yes
""")
enum_parsed = clarity.parse_ksy_structure(b"\x01\x44", enum_doc)
check("KSY enum ref + ternary value", enum_parsed["values"]["enum_probe.payload"] == 0x44 and enum_parsed["values"]["enum_probe.chosen"] == 7)


# Imports are actual vocabulary, not just ignored metadata: this is the shape of
# the upstream VFAT -> /common/dos_datetime relationship.  FAT16 keeps the
# specimen compact while still exercising imported nested types, integer `/`,
# out-of-line FAT/root-directory instances, and little-endian bit fields.
vfat_loaded = clarity.load_ksy("filesystem/vfat.ksy")
check("VFAT imports resolved", vfat_loaded is not None and "dos_datetime" in vfat_loaded[0]["__ksy_import_types__"])
vfat = bytearray(192)
vfat[0:3] = b"\xeb\x3c\x90"
vfat[3:11] = b"CLARITY "
# BPB: 64-byte logical sectors, one reserved sector, one FAT, one root entry.
bpb = struct.pack("<HBHBHHBHHHII", 64, 1, 1, 1, 1, 3, 0xf8, 1, 1, 1, 0, 0)
vfat[11:11 + len(bpb)] = bpb
pos = 11 + len(bpb)
vfat[pos:pos + 26] = bytes([0x80, 0, 0x29]) + b"\x12\x34\x56\x78" + b"CLARITY    " + b"FAT16   "
root = 128
vfat[root:root + 11] = b"HELLO   TXT"
vfat[root + 11] = 0x20
# DOS time/date: 12:34:56 on 2026-09-08.
time_word = 28 | (34 << 5) | (12 << 11)
date_word = 8 | (9 << 5) | ((2026 - 1980) << 9)
vfat[root + 22:root + 26] = struct.pack("<HH", time_word, date_word)
vfat[root + 26:root + 28] = struct.pack("<H", 2)
vfat[root + 28:root + 32] = struct.pack("<I", 123)
vfat_parsed = clarity.parse_ksy_structure(bytes(vfat), vfat_loaded[0])
check("VFAT integer division geometry", vfat_parsed["values"]["vfat.boot_sector.size_root_dir"] == 64)
check("VFAT imported DOS datetime", vfat_parsed["values"]["vfat.root_dir.records[0].last_write_time.date.year"] == 2026)
check("VFAT imported nested ternary/to_s", vfat_parsed["values"]["vfat.root_dir.records[0].last_write_time.date.padded_year"] == "2026")
check("VFAT root-directory field projection", vfat_parsed["values"]["vfat.root_dir.records[0].file_size"] == 123)
check("VFAT imported validity evidence", all(row["passed"] for row in vfat_parsed["constraints"] if "last_write_time" in row["path"]))

# SQLite forces a second independent import plus VLQ repeat-until, nested
# ternaries/casts, parameterized column types and an out-of-line cell pointer.
sqlite_loaded = clarity.load_ksy("database/sqlite3.ksy")
check("SQLite VLQ import resolved", sqlite_loaded is not None and "vlq_base128_be" in sqlite_loaded[0]["__ksy_import_types__"])
sqlite = bytearray(512)
sqlite[0:16] = b"SQLite format 3\0"
sqlite[16:18] = struct.pack(">H", 512)
sqlite[18:24] = bytes([1, 1, 0, 64, 32, 32])
header_u4 = [0, 1, 0, 0, 1, 4, 0, 0, 1, 0, 0, 0]
pos = 24
for value in header_u4:
    sqlite[pos:pos + 4] = struct.pack(">I", value)
    pos += 4
pos += 20
sqlite[pos:pos + 8] = struct.pack(">II", 0, 3040001)
# Root b-tree page starts at byte 100. One leaf-table cell lives at offset 120.
sqlite[100:108] = bytes([0x0d]) + struct.pack(">HHH", 0, 1, 120) + bytes([0])
sqlite[108:110] = struct.pack(">H", 120)
sqlite[120:125] = bytes([3, 1, 2, 15, ord("A")])
sqlite_parsed = clarity.parse_ksy_structure(bytes(sqlite), sqlite_loaded[0])
check("SQLite imported VLQ payload length", sqlite_parsed["values"]["sqlite3.root_page.cells[0].body.len_payload.value"] == 3)
check("SQLite imported VLQ rowid", sqlite_parsed["values"]["sqlite3.root_page.cells[0].body.row_id.value"] == 1)
check("SQLite serial integer division", sqlite_parsed["values"]["sqlite3.root_page.cells[0].body.payload.column_serials.entries[0].len_content"] == 1)
check("SQLite parameterized string column", sqlite_parsed["values"]["sqlite3.root_page.cells[0].body.payload.column_contents[0].as_str"] == "A")
check("SQLite out-of-line cell geometry", any(a["path"] == "sqlite3.root_page.cells[0].body" and a["start"] == 120 for a in sqlite_parsed["annotations"]))

# A parsed object now carries its actual substream. This is the generic shape
# needed by ext2-style `io: block[0].body._io` selectors.
io_doc = clarity.parse_ksy_yaml("""
meta:
  id: io_probe
seq:
  - id: ptr
    type: u1
  - id: box
    size: 4
    type: box
instances:
  reread:
    io: box._io
    pos: 1
    type: u1
types:
  box:
    seq:
      - id: raw
        size: 4
""")
io_parsed = clarity.parse_ksy_structure(bytes([0, 10, 20, 30, 40]), io_doc)
check("nested substream io selector", io_parsed["values"]["io_probe.reread"] == 20)

# ext2 and ISO9660 are real corpus examples with no root `seq` at all: the file
# is an address space and top-level instances point into it.  ext2 additionally
# proves that a nested alternate-stream instance stays genuinely lazy until the
# root-directory expression asks for exactly one inode's `as_dir` view.
ext2_loaded = clarity.load_ksy("filesystem/ext2.ksy")
check("ext2 instance-only root loaded", ext2_loaded is not None and "seq" not in ext2_loaded[0])
ext2 = bytearray(8192)
pos = 1024
for value in [2, 8, 0, 0, 0, 1, 0, 0, 8, 8, 2, 0, 0]:
    ext2[pos:pos + 4] = struct.pack("<I", value)
    pos += 4
for value in [0, 0]:
    ext2[pos:pos + 2] = struct.pack("<H", value)
    pos += 2
ext2[pos:pos + 2] = b"\x53\xef"
pos += 2
for value in [1, 1, 0]:
    ext2[pos:pos + 2] = struct.pack("<H", value)
    pos += 2
for value in [0, 0, 0, 1]:
    ext2[pos:pos + 4] = struct.pack("<I", value)
    pos += 4
for value in [0, 0]:
    ext2[pos:pos + 2] = struct.pack("<H", value)
    pos += 2
ext2[pos:pos + 4] = struct.pack("<I", 11)
pos += 4
ext2[pos:pos + 2] = struct.pack("<H", 128)
pos += 2
ext2[pos:pos + 2] = b"\0\0"
# First block-group descriptor says the inode table begins at block 5.
ext2[2048:2060] = struct.pack("<III", 3, 4, 5)
# inode #2 (index 1) is the root directory and points at data block 7.
inode2 = 5 * 1024 + 128
ext2[inode2:inode2 + 2] = struct.pack("<H", 0x4000)
ext2[inode2 + 4:inode2 + 8] = struct.pack("<I", 1024)
ext2[inode2 + 40:inode2 + 44] = struct.pack("<I", 7)
# One directory record consumes the full block, so repeat:eos terminates exactly.
dir_block = 7 * 1024
ext2[dir_block:dir_block + 4] = struct.pack("<I", 2)
ext2[dir_block + 4:dir_block + 6] = struct.pack("<H", 1024)
ext2[dir_block + 6] = 1
ext2[dir_block + 7] = 2
ext2[dir_block + 8] = ord(".")
ext2_parsed = clarity.parse_ksy_structure(bytes(ext2), ext2_loaded[0])
check("ext2 computed block size", ext2_parsed["values"]["ext2.bg1.super_block.block_size"] == 1024)
check("ext2 deferred inode table", ext2_parsed["values"]["ext2.bg1.block_groups[0].inodes[1].block[0].ptr"] == 7)
check("ext2 alternate-stream root directory", ext2_parsed["values"]["ext2.bg1.block_groups[0].inodes[1].as_dir.entries[0].name"] == ".")
check("ext2 root-directory value instance", isinstance(ext2_parsed["values"]["ext2.root_dir"], dict))
check("ext2 magic evidence", next(row for row in ext2_parsed["constraints"] if row["path"] == "ext2.bg1.super_block.magic")["passed"])

iso_loaded = clarity.load_ksy("filesystem/iso9660.ksy")
check("ISO9660 instance-only root loaded", iso_loaded is not None and "seq" not in iso_loaded[0])
iso = bytearray(19 * 2048)
pvd = 16 * 2048
iso[pvd] = 1
iso[pvd + 1:pvd + 6] = b"CD001"
iso[pvd + 6] = 1
pos = pvd + 7
iso[pos] = 0
pos += 1
iso[pos:pos + 32] = b"CLARITY" + b" " * 25
pos += 32
iso[pos:pos + 32] = b"TESTDISC" + b" " * 24
pos += 32
pos += 8
iso[pos:pos + 8] = struct.pack("<I", 19) + struct.pack(">I", 19)
pos += 8
iso[pos:pos + 4] = struct.pack("<H", 2048) + struct.pack(">H", 2048)
pos += 4
iso[pos:pos + 4] = struct.pack("<I", 18)
path = 18 * 2048
iso[path:path + 10] = bytes([1, 0]) + struct.pack("<I", 20) + struct.pack("<H", 1) + b"\0\0"
iso_parsed = clarity.parse_ksy_structure(bytes(iso), iso_loaded[0])
check("ISO9660 primary-volume instance", iso_parsed["values"]["iso9660.primary_vol_desc.magic"] == b"CD001")
check("ISO9660 both-endian integer", iso_parsed["values"]["iso9660.primary_vol_desc.vol_desc_primary.vol_space_size.le"] == 19 and iso_parsed["values"]["iso9660.primary_vol_desc.vol_desc_primary.vol_space_size.be"] == 19)
check("ISO9660 out-of-line path table", iso_parsed["values"]["iso9660.primary_vol_desc.vol_desc_primary.path_table.entries[0].lba_extent"] == 20)

# Bit runs are allowed to sit between ordinary byte fields (FAT32 does this),
# and SQLite's less-common numeric serial forms require wide bN + f8 primitives.
bitmix_doc = clarity.parse_ksy_yaml("""
meta:
  id: bitmix_probe
  bit-endian: le
seq:
  - id: prefix
    type: u1
  - id: enabled
    type: b1
  - id: reserved
    type: b3
  - id: slot
    type: b4
  - id: suffix
    type: u1
""")
bitmix = clarity.parse_ksy_structure(bytes([0xaa, 0x51, 0xbb]), bitmix_doc)
check("mixed byte/bit/byte cursor", bitmix["values"]["bitmix_probe.enabled"] == 1 and bitmix["values"]["bitmix_probe.slot"] == 5 and bitmix["values"]["bitmix_probe.suffix"] == 0xbb)
wide_doc = clarity.parse_ksy_yaml("""
meta:
  id: wide_probe
  endian: be
seq:
  - id: u24
    type: b24
  - id: u48
    type: b48
  - id: real
    type: f8
""")
wide_bytes = bytes.fromhex("010203010203040506") + struct.pack(">d", 1.25)
wide = clarity.parse_ksy_structure(wide_bytes, wide_doc)
check("wide b24/b48 fields", wide["values"]["wide_probe.u24"] == 0x010203 and wide["values"]["wide_probe.u48"] == 0x010203040506)
check("f8 primitive", math.isclose(wide["values"]["wide_probe.real"], 1.25, abs_tol=0.0))

print(f"Clarity metrology: {len(checks)}/{len(checks)} exact checks")
PY

# Explicit KSY projection is a generic CLI surface, not a format-specific mode.
python3 - <<'PAKGEN' > "$tmp/mini.pak"
import struct, sys
b0 = b"HELLO"
b1 = b"WORLD!!"
index_offset = 12 + len(b0) + len(b1)
entries = b""
for name, ofs, body in (("a.txt", 12, b0), ("b.bin", 12 + len(b0), b1)):
    entries += name.encode().ljust(56, b"\0") + struct.pack("<II", ofs, len(body))
sys.stdout.buffer.write(b"PACK" + struct.pack("<II", index_offset, len(entries)) + b0 + b1 + entries)
PAKGEN
python3 clarity.py --ksy game/quake_pak.ksy --json "$tmp/mini.pak" > "$tmp/pak-projection.json"
python3 - "$tmp/pak-projection.json" <<'PAKCHECK'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
projection = obj["ksy_projections"][0]
assert projection["ksy_id"] == "quake_pak"
assert projection["values"]["quake_pak.index.entries[0].name"] == "a.txt"
assert any(
    row["path"] == "quake_pak.index.entries[1].body" and row["start"] == 17 and row["end"] == 24
    for row in projection["annotations"]
)
PAKCHECK

# Raw statistics remain available without interpretation; --stats is explicit STFU mode.
python3 clarity.py "$tmp/probe-xor.grb" > "$tmp/default-stats.txt"
python3 clarity.py --stats "$tmp/probe-xor.grb" > "$tmp/explicit-stats.txt"
cmp "$tmp/default-stats.txt" "$tmp/explicit-stats.txt"
if grep -q '^CLAIM:' "$tmp/explicit-stats.txt"; then
    echo "FAIL: --stats emitted interpretation" >&2
    exit 1
fi
# Human-readable byte aliases are notation, not interpretation.
printf 'EEEEKKK\n\n' > "$tmp/ascii-stats.bin"
python3 clarity.py --stats "$tmp/ascii-stats.bin" > "$tmp/ascii-stats.txt"
grep -q "45: .*ASCII 'E'" "$tmp/ascii-stats.txt"
grep -q "0a: .*LF" "$tmp/ascii-stats.txt"

# --analyze may claim observed periodicity but must abstain from naming a transform family.
python3 - <<'PY' > "$tmp/periodic.bin"
import sys
sys.stdout.buffer.write((b"abc" * 4096))
PY
python3 clarity.py --analyze "$tmp/periodic.bin" > "$tmp/analyze.txt"
grep -q '^CLAIM: strong byte-coincidence periodicity' "$tmp/analyze.txt"
grep -q 'fundamental lag: 3 bytes' "$tmp/analyze.txt"
grep -q '^ABSTAIN: transform family' "$tmp/analyze.txt"

# Structure map is first-class in --analyze and stays byte-character evidence, not
# an invented format identity. Four exact 1024-byte regions exercise merge/boundary logic.
python3 - <<'PY' > "$tmp/mixed-structure.bin"
import random, sys
rng = random.Random(0x57A7)
text = (b"int main(void) { return 0; }\n" * 40)[:1024].ljust(1024, b" ")
fill = b"\xff" * 1024
high = bytes(rng.randrange(256) for _ in range(1024))
other = (bytes(range(32)) * 32)[:1024]
sys.stdout.buffer.write(text + fill + high + other)
PY
python3 clarity.py --json "$tmp/mixed-structure.bin" > "$tmp/mixed-structure.json"
python3 - "$tmp/mixed-structure.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
regions = obj["structure"]["regions"]
assert [(r["start"], r["end"], r["kind"]) for r in regions] == [
    (0, 1024, "ascii_compatible"),
    (1024, 2048, "fill"),
    (2048, 3072, "high_entropy"),
    (3072, 4096, "other"),
]
assert regions[1]["fill_byte"] == 0xff
PY

# MBR is the first structured "view": exact field ranges remain available in JSON,
# while a damaged signature keeps the useful shape but loses the identity claim.
python3 - <<'PY' > "$tmp/mbr.bin"
import sys
b = bytearray(512)
b[:4] = b"\xfa\x31\xc0\x8e"
p = 0x1be
b[p] = 0x80
b[p + 4] = 0x83
b[p + 8:p + 12] = (2048).to_bytes(4, "little")
b[p + 12:p + 16] = (409600).to_bytes(4, "little")
b[510:512] = b"\x55\xaa"
sys.stdout.buffer.write(b)
PY
CLARITY_KSY_ROOT= python3 clarity.py --ksy-root "$tmp/kaitai" --json --base-offset 0x2000 "$tmp/mbr.bin" > "$tmp/mbr.json"
printf 'BAD!!\001\002\003\004' > "$tmp/poison-auto.bin"
python3 clarity.py --json --windowed --max-lag 16 "$tmp/poison-auto.bin" > "$tmp/poison-auto.json"
python3 - "$tmp/poison-auto.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert isinstance(obj.get("views"), list)
assert not any(v.get("ksy_id") == "poison_auto" for v in obj["views"])
PY
python3 - "$tmp/mbr.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
claims = [c for c in obj["claims"] if c["kind"] == "mbr_partition_table"]
assert len(claims) == 1 and claims[0]["offset"] == 0x2000
assert obj["base_offset"] == 0x2000
view = obj["views"][0]
assert view["strong_identity"] is True
assert view["shape_source"] == "kaitai/filesystem/mbr_partition_table.ksy"
by_path = {a["path"]: a for a in view["annotations"]}
assert (by_path["mbr.bootstrap_code"]["start"], by_path["mbr.bootstrap_code"]["end"]) == (0x2000, 0x21be)
assert (by_path["mbr.partitions[0].lba_start"]["start"], by_path["mbr.partitions[0].lba_start"]["end"]) == (0x21c6, 0x21ca)
assert by_path["mbr.partitions[0].lba_start"]["value"] == 2048
PY
cp "$tmp/mbr.bin" "$tmp/mbr-damaged.bin"
printf '\0\0' | dd of="$tmp/mbr-damaged.bin" bs=1 seek=510 conv=notrunc status=none
python3 clarity.py --json "$tmp/mbr-damaged.bin" > "$tmp/mbr-damaged.json"
python3 - "$tmp/mbr-damaged.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert not [c for c in obj["claims"] if c["kind"] == "mbr_partition_table"]
assert len(obj["views"]) == 1
view = obj["views"][0]
assert view["checks_passed"] == 9 and not view["strong_identity"]
assert "boot signature 55 aa absent" in view["hard_contradictions"]
PY

# A structurally consistent ELF hidden behind unrelated bytes should earn identity;
# a magic string alone is never enough.
python3 - <<'PY' > "$tmp/embedded-elf.bin"
import sys
prefix = b"wrapper-not-elf:" + bytes(range(16))
eh = bytearray(64)
eh[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
eh[16:18] = (2).to_bytes(2, "little")
eh[18:20] = (62).to_bytes(2, "little")
eh[20:24] = (1).to_bytes(4, "little")
eh[32:40] = (64).to_bytes(8, "little")
eh[52:54] = (64).to_bytes(2, "little")
eh[54:56] = (56).to_bytes(2, "little")
eh[56:58] = (1).to_bytes(2, "little")
eh[58:60] = (64).to_bytes(2, "little")
ph = bytearray(56)
ph[0:4] = (1).to_bytes(4, "little")
ph[4:8] = (5).to_bytes(4, "little")
ph[8:16] = (120).to_bytes(8, "little")
ph[32:40] = (32).to_bytes(8, "little")
ph[40:48] = (32).to_bytes(8, "little")
ph[48:56] = (4096).to_bytes(8, "little")
payload = bytes(range(32))
sys.stdout.buffer.write(prefix + eh + ph + payload + b"tail")
PY
python3 clarity.py --analyze "$tmp/embedded-elf.bin" > "$tmp/embedded-elf.txt"
grep -q '^CLAIM: structurally validated embedded ELF object' "$tmp/embedded-elf.txt"
grep -q 'class/endian: ELF64 little-endian' "$tmp/embedded-elf.txt"
grep -q 'minimum structurally referenced extent: 152 bytes' "$tmp/embedded-elf.txt"

# Known-plaintext relation discovery remains generic: no Garble parser is involved.
python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-xor.grb" > "$tmp/xor-known.txt"
grep -q 'exact repeating XOR-mask period: 10 bytes' "$tmp/xor-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/xor-known.txt"
grep -q 'PR:\[hex=426c756556656c766574' "$tmp/xor-known.txt"

python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/subst-known.txt"
grep -q 'exact position-independent one-byte substitution relation' "$tmp/subst-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/subst-known.txt"
grep -q 'observed plaintext symbols mapped consistently: 256/256' "$tmp/subst-known.txt"
grep -q 'recovered mapping: PR:\[' "$tmp/subst-known.txt"

python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle-known.txt"
grep -q 'exact fixed within-block position-permutation relation across complete blocks' "$tmp/shuffle-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/shuffle-known.txt"
grep -q 'smallest supported block size: 16 bytes' "$tmp/shuffle-known.txt"
grep -q 'trailing bytes outside this claim: 8' "$tmp/shuffle-known.txt"
grep -q 'recovered position mapping: PR:\[out->in ' "$tmp/shuffle-known.txt"

# --private suppresses all recovered key/mapping material while retaining diagnosis.
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-xor.grb" > "$tmp/xor-private.txt"
grep -q 'PR:\[redacted by --private\]' "$tmp/xor-private.txt"
if grep -q '426c756556656c766574' "$tmp/xor-private.txt"; then
    echo "FAIL: --private leaked recovered XOR mask" >&2
    exit 1
fi
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/subst-private.txt"
grep -q 'recovered mapping: PR:\[redacted by --private\]' "$tmp/subst-private.txt"
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle-private.txt"
grep -q 'recovered position mapping: PR:\[redacted by --private\]' "$tmp/shuffle-private.txt"

# JSON is the scoring contract: tests inspect claims, never English phrasing.
python3 clarity.py --json --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/result.json"
python3 - "$tmp/result.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["stats"]["bytes"] > 0
assert isinstance(obj["claims"], list)
assert isinstance(obj["abstentions"], list)
assert isinstance(obj["views"], list)
assert obj["base_offset"] == 0
assert obj["known_plaintext"]["kind"] == "fixed_byte_substitution"
assert obj["known_plaintext"]["offset"] == 16
assert obj["known_plaintext"]["observed_symbols"] == 256
assert obj["known_plaintext"]["mapping_pr"].startswith("PR:[")
PY
python3 clarity.py --json --private --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/private.json"
python3 - "$tmp/private.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["known_plaintext"]["mapping_pr"] == "PR:[redacted by --private]"
PY
python3 clarity.py --json --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle.json"
python3 - "$tmp/shuffle.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["known_plaintext"]["kind"] == "fixed_block_position_permutation"
assert obj["known_plaintext"]["offset"] == 16
assert obj["known_plaintext"]["block_size"] == 16
assert obj["known_plaintext"]["verified_bytes"] % 16 == 0
assert obj["known_plaintext"]["trailing_bytes"] == 8
assert obj["known_plaintext"]["mapping_pr"].startswith("PR:[out->in ")
PY

# --- Bullshit-fuzzer 1: ciphertext-only periodicity claim vs hostile near-misses. ---
# Exactly 300 deterministic specimens. A wrong period is a false claim, not a near miss.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xC1A17A)
tp = fp = fn = tn = wrong = 0

# 100 true periodic specimens, fundamental periods 2..64.
for _ in range(100):
    p = rng.randint(2, 64)
    while True:
        unit = bytes(rng.randrange(256) for _ in range(p))
        if clarity.smallest_period_exact(unit * 3, p) == p:
            break
    data = (unit * ((4096 // p) + 2))[:4096]
    claim = clarity.periodicity_claim(data, 128)
    if claim is None:
        fn += 1
    elif claim["period"] == p:
        tp += 1
    else:
        wrong += 1
        fn += 1

# 75 uniform-random negatives.
for _ in range(75):
    data = bytes(rng.randrange(256) for _ in range(4096))
    if clarity.periodicity_claim(data, 128) is None:
        tn += 1
    else:
        fp += 1

# 75 heavily biased but independent negatives: low entropy alone must not become "periodic".
for _ in range(75):
    alphabet = bytes(range(rng.randint(2, 24)))
    data = bytes(rng.choice(alphabet) for _ in range(4096))
    if clarity.periodicity_claim(data, 128) is None:
        tn += 1
    else:
        fp += 1

# 50 run-heavy/Markov-ish negatives: strong serial correlation is not periodicity.
for _ in range(50):
    b = bytearray()
    while len(b) < 4096:
        b.extend([rng.randrange(256)] * rng.randint(1, 24))
    if clarity.periodicity_claim(bytes(b[:4096]), 128) is None:
        tn += 1
    else:
        fp += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "Ciphertext-only periodicity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.90:
    raise SystemExit("FAIL: periodicity claim has not earned its threshold")
PY

# --- Bullshit-fuzzer 2: known-plaintext relation families, independent of Garble. ---
# 300 more deterministic specimens: XOR, arbitrary substitution, modular ADD, unrelated random.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x51A7E)
correct = wrong = abstain = 0


def fundamental_key(n):
    while True:
        key = bytes(rng.randrange(256) for _ in range(n))
        if clarity.smallest_period_exact(key * 2, n) == n:
            return key


def wrap(payload):
    pre = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    post = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    return pre + payload + post, len(pre)


def plain_bytes():
    # Repeated values across many positions make one-byte relation claims falsifiable.
    b = bytearray(bytes(range(256)) * 3)
    b.extend(rng.randrange(256) for _ in range(256))
    return bytes(b)

# 100 exact repeating XOR relationships.
for _ in range(100):
    plain = plain_bytes()
    klen = rng.randint(2, 31)
    key = fundamental_key(klen)
    payload = bytes(b ^ key[i % klen] for i, b in enumerate(plain))
    cipher, off = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        abstain += 1
    elif found["kind"] == "repeating_xor" and found["offset"] == off and found["period"] == klen:
        correct += 1
    else:
        wrong += 1

# 100 arbitrary fixed substitutions. These do not use Garble's permutation generator.
for _ in range(100):
    plain = plain_bytes()
    table = list(range(256))
    rng.shuffle(table)
    payload = bytes(table[b] for b in plain)
    cipher, off = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        abstain += 1
    elif found["kind"] == "fixed_byte_substitution" and found["offset"] == off:
        correct += 1
    else:
        wrong += 1

# 50 position-dependent modular ADD near-misses: neither exact XOR nor fixed substitution.
for _ in range(50):
    plain = plain_bytes()
    klen = rng.randint(2, 31)
    key = fundamental_key(klen)
    payload = bytes((b + key[i % klen]) & 0xff for i, b in enumerate(plain))
    cipher, _ = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        correct += 1
    else:
        wrong += 1

# 50 unrelated random near-misses.
for _ in range(50):
    plain = plain_bytes()
    payload = bytes(rng.randrange(256) for _ in range(len(plain)))
    cipher, _ = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        correct += 1
    else:
        wrong += 1

claims = correct + wrong
precision = correct / claims if claims else 1.0
coverage = claims / 300
print(
    "Known-plaintext relation corpus: "
    f"correct={correct} wrong={wrong} abstain={abstain} "
    f"precision={precision:.2%} answered={coverage:.2%}"
)
if wrong != 0:
    raise SystemExit("FAIL: known-plaintext relation detector made a false claim")
if correct < 295:
    raise SystemExit("FAIL: known-plaintext relation detector abstains too often on known-truth corpus")
PY

# --- Bullshit-fuzzer 3: fixed within-block position permutation vs near-miss families. ---
# Another 300 deterministic specimens. The detector gets known plaintext but no transform metadata.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xB10C5)
tp = fp = fn = tn = wrong = 0

def wrap(payload):
    pre = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    post = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    return pre + payload + post, len(pre)

def plain_for(block_size, trailing=0):
    return bytes(rng.randrange(256) for _ in range(block_size * 40 + trailing))

def shuffled_full_blocks(plain, block_size, perm, hostile_tail=False):
    full = (len(plain) // block_size) * block_size
    out = bytearray()
    for off in range(0, full, block_size):
        block = plain[off:off + block_size]
        out.extend(block[i] for i in perm)
    tail = plain[full:]
    if hostile_tail:
        # Deliberately do something unrelated to the tail. The detector's claim is
        # scoped to complete blocks and must report, not silently absorb, this gap.
        out.extend(((b + 73) & 0xff) for b in tail)
    else:
        out.extend(tail)
    return bytes(out)

# 100 true block permutations, varying block sizes and arbitrary maps independent of Garble.
# Half include an adversarial short tail to verify that Clarity scopes the claim honestly.
for case in range(100):
    block_size = rng.randint(3, 32)
    trailing = 0 if case < 50 else rng.randint(1, block_size - 1)
    plain = plain_for(block_size, trailing)
    while True:
        perm = list(range(block_size))
        rng.shuffle(perm)
        if perm != list(range(block_size)):
            break
    cipher, off = wrap(shuffled_full_blocks(plain, block_size, perm, hostile_tail=bool(trailing)))
    found = clarity.best_known_plaintext_block_permutation(cipher, plain, 64)
    if found is None:
        fn += 1
    elif (
        found["offset"] == off
        and found["block_size"] == block_size
        and found["mapping"] == perm
        and found["trailing_bytes"] == trailing
        and found["verified_bytes"] == len(plain) - trailing
    ):
        tp += 1
    else:
        wrong += 1
        fn += 1

# 60 fixed byte substitutions: values change, positions do not.
for _ in range(60):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    table = list(range(256))
    rng.shuffle(table)
    cipher, _ = wrap(bytes(table[b] for b in plain))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 60 repeating XOR near-misses.
for _ in range(60):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    key = bytes(rng.randrange(256) for _ in range(rng.randint(2, 17)))
    cipher, _ = wrap(bytes(b ^ key[i % len(key)] for i, b in enumerate(plain)))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 40 modular-ADD near-misses.
for _ in range(40):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    key = bytes(rng.randrange(256) for _ in range(rng.randint(2, 17)))
    cipher, _ = wrap(bytes((b + key[i % len(key)]) & 0xff for i, b in enumerate(plain)))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 40 unrelated random payloads.
for _ in range(40):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    payload = bytes(rng.randrange(256) for _ in range(len(plain)))
    cipher, _ = wrap(payload)
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "Known-plaintext block-permutation corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.90:
    raise SystemExit("FAIL: block-permutation relation has not earned its threshold")
PY

# --- Bullshit-fuzzer 4: coarse structure character, including an explicit OTHER lane. ---
# 300 deterministic windows. These labels describe measured byte character only; they
# intentionally do not pretend that printable bytes are prose or high entropy is encryption.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x5712C7)
correct = wrong = 0

def judge(data, expected):
    global correct, wrong
    got = clarity.structural_character(data)["kind"]
    if got == expected:
        correct += 1
    else:
        wrong += 1

for _ in range(75):
    value = rng.randrange(256)
    data = bytearray([value] * 1024)
    for _ in range(rng.randrange(0, 10)):
        data[rng.randrange(len(data))] = rng.randrange(256)
    judge(bytes(data), "fill")

alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-:;,.(){}[]/\\\n\t"
for _ in range(75):
    data = bytes(rng.choice(alphabet) for _ in range(1024))
    judge(data, "ascii_compatible")

for _ in range(75):
    data = bytes(rng.randrange(256) for _ in range(1024))
    judge(data, "high_entropy")

for _ in range(75):
    alphabet2 = bytes([0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23])
    data = bytes(rng.choice(alphabet2) for _ in range(1024))
    judge(data, "other")

print(f"Structure-character corpus: correct={correct} wrong={wrong} precision={correct/(correct+wrong):.2%}")
if wrong:
    raise SystemExit("FAIL: coarse structure character mislabeled generated ground truth")
PY

# --- Bullshit-fuzzer 5: ELF identity must be structural, never magic-number enthusiasm. ---
# 300 deterministic specimens: valid embedded ELF32/ELF64, malformed magic-bearing decoys,
# and unrelated random data. The positive generator uses only the public ELF layout.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xE1F1D)
tp = fp = fn = tn = wrong = 0

def noise(n):
    while True:
        b = bytes(rng.randrange(256) for _ in range(n))
        if b"\x7fELF" not in b:
            return b

def put(buf, off, size, value, order):
    buf[off:off+size] = value.to_bytes(size, order)

def make_elf(bits, order):
    if bits == 32:
        ehsize, phentsize, payload_off, machine = 52, 32, 84, 3
    else:
        ehsize, phentsize, payload_off, machine = 64, 56, 120, 62
    payload_len = rng.randrange(16, 97)
    eh = bytearray(ehsize)
    eh[:16] = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if order == "little" else 2, 1, 0]) + bytes(8)
    put(eh, 16, 2, rng.choice((1, 2, 3)), order)
    put(eh, 18, 2, machine, order)
    put(eh, 20, 4, 1, order)
    if bits == 32:
        put(eh, 28, 4, ehsize, order)
        put(eh, 40, 2, ehsize, order)
        put(eh, 42, 2, phentsize, order)
        put(eh, 44, 2, 1, order)
        put(eh, 46, 2, 40, order)
        ph = bytearray(phentsize)
        put(ph, 0, 4, 1, order)
        put(ph, 4, 4, payload_off, order)
        put(ph, 16, 4, payload_len, order)
        put(ph, 20, 4, payload_len, order)
        put(ph, 24, 4, 5, order)
        put(ph, 28, 4, 4096, order)
    else:
        put(eh, 32, 8, ehsize, order)
        put(eh, 52, 2, ehsize, order)
        put(eh, 54, 2, phentsize, order)
        put(eh, 56, 2, 1, order)
        put(eh, 58, 2, 64, order)
        ph = bytearray(phentsize)
        put(ph, 0, 4, 1, order)
        put(ph, 4, 4, 5, order)
        put(ph, 8, 8, payload_off, order)
        put(ph, 32, 8, payload_len, order)
        put(ph, 40, 8, payload_len, order)
        put(ph, 48, 8, 4096, order)
    payload = noise(payload_len)
    return bytes(eh + ph + payload), payload_off + payload_len

for _ in range(100):
    bits = rng.choice((32, 64))
    order = rng.choice(("little", "big"))
    elf, extent = make_elf(bits, order)
    pre = noise(rng.randrange(0, 65))
    blob = pre + elf + noise(rng.randrange(0, 65))
    claims = clarity.elf_identity_claims(blob)
    if not claims:
        fn += 1
    elif len(claims) == 1 and claims[0]["offset"] == len(pre) and claims[0]["class_bits"] == bits and claims[0]["endian"] == order and claims[0]["minimum_referenced_extent"] == extent:
        tp += 1
    else:
        wrong += 1
        fn += 1

for case in range(100):
    bits = rng.choice((32, 64))
    order = rng.choice(("little", "big"))
    elf, _ = make_elf(bits, order)
    bad = bytearray(elf)
    mode = case % 5
    if mode == 0:
        bad[4] = 0
    elif mode == 1:
        bad[6] = 2
    elif mode == 2:
        bad[18:20] = b"\0\0"
    elif mode == 3:
        off = 40 if bits == 32 else 52
        bad[off:off+2] = (1).to_bytes(2, order)
    else:
        if bits == 32:
            ph = 52
            bad[ph+16:ph+20] = (0x7fffffff).to_bytes(4, order)
        else:
            ph = 64
            bad[ph+32:ph+40] = (0x7fffffffffffffff).to_bytes(8, order)
    blob = noise(rng.randrange(0, 65)) + bytes(bad) + noise(rng.randrange(0, 65))
    if clarity.elf_identity_claims(blob):
        fp += 1
    else:
        tn += 1

for _ in range(100):
    blob = noise(rng.randrange(128, 4097))
    if clarity.elf_identity_claims(blob):
        fp += 1
    else:
        tn += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "ELF identity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.95:
    raise SystemExit("FAIL: ELF identity claim has not earned its threshold")
PY

# --- Bullshit-fuzzer 6: MBR strong identity vs partial surviving form vs noise. ---
# 300 deterministic sectors. Missing-signature specimens must retain a useful view
# but may not be promoted to identity; random aligned sectors must do neither.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x4D4252)
tp = fp = fn = tn = wrong = 0
partial_ok = partial_wrong = 0

def make_mbr():
    b = bytearray(rng.randrange(256) for _ in range(446))
    b.extend(bytes(66))
    count = rng.randint(1, 4)
    used = sorted(rng.sample(range(4), count))
    next_lba = rng.randint(1, 4096)
    for i in used:
        p = 0x1be + 16 * i
        b[p] = 0x80 if i == used[0] and rng.randrange(2) else 0
        # CHS is intentionally arbitrary legacy metadata; Clarity does not use it.
        b[p+1:p+4] = bytes(rng.randrange(256) for _ in range(3))
        b[p+4] = rng.choice((0x01, 0x04, 0x06, 0x07, 0x0b, 0x0c, 0x0e, 0x82, 0x83, 0xee))
        b[p+5:p+8] = bytes(rng.randrange(256) for _ in range(3))
        sectors = rng.randint(1, 2_000_000)
        b[p+8:p+12] = next_lba.to_bytes(4, "little")
        b[p+12:p+16] = sectors.to_bytes(4, "little")
        next_lba = min(0xffffffff, next_lba + sectors)
    b[510:512] = b"\x55\xaa"
    return bytes(b)

for _ in range(100):
    sector = make_mbr()
    prefix_sectors = rng.randrange(0, 9)
    pre = b"".join(bytes(rng.randrange(256) for _ in range(512)) for _ in range(prefix_sectors))
    blob = pre + sector
    claims = clarity.mbr_identity_claims(blob)
    expected = prefix_sectors * 512
    if not claims:
        fn += 1
    elif len(claims) == 1 and claims[0]["offset"] == expected and claims[0]["checks_passed"] == 10:
        tp += 1
    else:
        wrong += 1
        fn += 1

for _ in range(100):
    sector = bytearray(make_mbr())
    sector[510:512] = b"\0\0"
    views = clarity.mbr_views(bytes(sector))
    claims = clarity.mbr_identity_claims(bytes(sector))
    if len(views) == 1 and views[0]["checks_passed"] == 9 and not views[0]["strong_identity"] and not claims:
        partial_ok += 1
    else:
        partial_wrong += 1
        if claims:
            fp += 1

for _ in range(100):
    while True:
        sector = bytearray(rng.randrange(256) for _ in range(512))
        sector[510:512] = b"\0\0"
        if clarity.mbr_view_at(bytes(sector), 0) is None:
            break
    if clarity.mbr_identity_claims(bytes(sector)) or clarity.mbr_views(bytes(sector)):
        fp += 1
    else:
        tn += 1

assert tp + fn == 100
assert partial_ok + partial_wrong == 100
assert fp + tn == 100
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "MBR structure/identity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"partial={partial_ok}/100 precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.95 or partial_wrong:
    raise SystemExit("FAIL: MBR structure/identity behavior has not earned its threshold")
PY

echo "PASS: mechanics + metrology + stats/analyze/JSON contracts + 1800-case claim/abstain truth universe"
