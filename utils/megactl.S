.global megactl
.global megactl_size
.global megasasctl
.global megasasctl_size

megactl:
  .incbin "megactl/src/megactl"

1:
megactl_size:
  .int 1b - megactl

megasasctl:
  .incbin "megactl/src/megasasctl"

2:
megasasctl_size:
  .int 2b - megasasctl
