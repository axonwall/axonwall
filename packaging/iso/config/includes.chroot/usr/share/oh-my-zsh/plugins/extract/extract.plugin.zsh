# ==============================================================================
# Oh My Zsh — extract plugin
# Universal archive extractor (tar, gz, xz, zst, bz2, zip, deb, 7z)
# ==============================================================================

alias x=extract

extract() {
  if (( $# == 0 )); then
    echo "Usage: extract <archive_file> ..." >&2
    return 1
  fi
  while (( $# > 0 )); do
    if [[ ! -f "$1" ]]; then
      echo "extract: '$1' is not a valid file" >&2
      shift
      continue
    fi
    case "${1:l}" in
      *.tar.gz|*.tgz)   tar xvzf "$1" ;;
      *.tar.bz2|*.tbz2) tar xvjf "$1" ;;
      *.tar.xz|*.txz)   tar xvJf "$1" ;;
      *.tar.zst)        tar --zstd -xvf "$1" ;;
      *.tar)            tar xvf "$1" ;;
      *.gz)             gunzip -k "$1" ;;
      *.bz2)            bunzip2 "$1" ;;
      *.xz)             unxz "$1" ;;
      *.zst)            unzstd "$1" ;;
      *.zip)            unzip "$1" ;;
      *.deb)            ar x "$1" ;;
      *.7z)             7z x "$1" ;;
      *) echo "extract: '$1' cannot be extracted via extract()" >&2 ;;
    esac
    shift
  done
}
