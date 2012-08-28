.global smartctl
.global smartctl_size

smartctl:
  .incbin "smartmontools/smartctl"

1:
smartctl_size:
  .int 1b - smartctl
