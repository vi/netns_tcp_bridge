targetsettings() {
  MINI=1
  case "$1" in
     *freebsd*)
          SKIP=1
     ;;
     *windows*)
          SKIP=1
     ;;
     *darwin*)
          SKIP=1
     ;;
     wasm32-wasip1)
          SKIP=1
     ;;
     loongarch64-unknown-linux-musl)
         MINI=0
     ;;
     riscv64gc-unknown-linux-musl)
         MINI=0
     ;;
  esac
}
