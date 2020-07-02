import logging
import os
import struct

TYPE_BOOLEAN = 1
TYPE_INT8 = 2
TYPE_INT16 = 3
TYPE_INT32 = 4
TYPE_MONEY = 5
TYPE_FLOAT32 = 6
TYPE_FLOAT64 = 7
TYPE_DATETIME = 8
TYPE_BINARY = 9
TYPE_TEXT = 10
TYPE_OLE = 11
TYPE_MEMO = 12
TYPE_GUID = 15
TYPE_96_bit_17_BYTES = 16
TYPE_COMPLEX = 18

TABLE_PAGE_MAGIC = b"\x02\x01"
DATA_PAGE_MAGIC = b"\x01\x01"


def parse_type(data_type, buffer, length=None, version=3):
    parsed = ""
    # Bool or int8
    if data_type == TYPE_INT8:
        parsed = struct.unpack_from("b", buffer)[0]
    elif data_type == TYPE_INT16:
        parsed = struct.unpack_from("h", buffer)[0]
    elif data_type == TYPE_INT32 or data_type == TYPE_COMPLEX:
        parsed = struct.unpack_from("i", buffer)[0]
    elif data_type == TYPE_MONEY:
        parsed = struct.unpack_from("q", buffer)[0]
    elif data_type == TYPE_FLOAT32:
        parsed = struct.unpack_from("f", buffer)[0]
    elif data_type == TYPE_FLOAT64:
        parsed = struct.unpack_from("d", buffer)[0]
    elif data_type == TYPE_DATETIME:
        parsed = struct.unpack_from("q", buffer)[0]
    elif data_type == TYPE_BINARY:
        parsed = buffer[:length]
        offset = length
    elif data_type == TYPE_GUID:
        parsed = buffer[:16]
    elif data_type == TYPE_96_bit_17_BYTES:
        parsed = buffer[:17]
    elif data_type == TYPE_TEXT:
        if version > 3:
            # Looks like if BOM is present text is already decoded
            if buffer.startswith(b"\xfe\xff") or buffer.startswith(b"\xff\xfe"):
                buff = buffer[2:]
                parsed = buff.decode("utf-8", errors='ignore')
            else:
                parsed = buffer.decode("utf-16", errors='ignore')
        else:
            parsed = buffer.decode('utf-8', errors='ignore')
    else:
        logging.debug(f"parse_type - unsupported data type: {data_type}")
    return parsed


def categorize_pages(db_data, page_size):
    if len(db_data) % page_size:
        logging.warning(f"DB is not full or PAGE_SIZE is wrong. page size: {page_size} DB length {len(db_data)}")
    pages = {i: db_data[i:i + page_size] for i in range(0, len(db_data), page_size)}
    data_pages = {}
    table_defs = {}
    for page in pages:
        if pages[page].startswith(DATA_PAGE_MAGIC):
            data_pages[page] = pages[page]
        elif pages[page].startswith(TABLE_PAGE_MAGIC):
            table_defs[page] = pages[page]
    return table_defs, data_pages, pages


def read_db_file(path):
    if not os.path.isfile(path):
        logging.error(f"File {path} not found")
        raise FileNotFoundError(f"File {path} not found")
    with open(path, "rb") as f:
        return f.read()
