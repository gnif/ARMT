.global cciss_vol_status
.global cciss_vol_status_size

cciss_vol_status:
  .incbin "cciss_vol_status/cciss_vol_status"

1:
cciss_vol_status_size:
  .int 1b - cciss_vol_status
