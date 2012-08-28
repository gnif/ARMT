.global lsscsi
.global lsscsi_size

lsscsi:
  .incbin "lsscsi/src/lsscsi"

1:
lsscsi_size:
  .int 1b - lsscsi
