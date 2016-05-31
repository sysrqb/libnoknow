#!/bin/sh
PYTHONPATH=../trunnel/lib/ python -m trunnel src/ipc_protocol.trunnel
mv src/ipc_protocol.h include/internal/
sed --in-place -e 's,"ipc_protocol.h",<internal/ipc_protocol.h>,' -e 's,"trunnel.h",<internal/trunnel.h>,' -e 's,"trunnel-impl.h",<internal/trunnel-impl.h>,' -e 's/\([a-z0-9_]* \*\)val =/\1val = (\1)/' -e 's/trunnel_malloc/(char *) trunnel_malloc/' -e 's/trunnel_dynarray_setlen/(uint32_t *) trunnel_dynarray_setlen/' src/ipc_protocol.c
