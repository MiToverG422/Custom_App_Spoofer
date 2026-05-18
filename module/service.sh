#!/system/bin/sh

MODDIR="${0%/*}"
LOGDIR="$MODDIR/logs"
LOGFILE="$LOGDIR/runtime.log"

mkdir -p "$LOGDIR"

{
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh module_loaded path=$MODDIR"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh zygisk_arm64=$([ -f "$MODDIR/zygisk/arm64-v8a.so" ] && echo yes || echo no) hooker_dex=$([ -f "$MODDIR/hooker.dex" ] && echo yes || echo no) config=$([ -f "$MODDIR/config/config.toml" ] && echo yes || echo no)"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh abi=$(getprop ro.product.cpu.abilist) zygote=$(pidof zygote64 2>/dev/null || pidof zygote 2>/dev/null || echo none)"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh providers=$(ls /data/adb/modules 2>/dev/null | grep -Ei 'zygisk|rezygisk|neozygisk' | tr '\n' ',' || echo none)"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh so_perm=$(ls -l "$MODDIR/zygisk/arm64-v8a.so" 2>/dev/null)"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [I] service.sh note=If only service.sh lines appear after opening apps, check the Zygisk provider or native module load errors."
} >> "$LOGFILE"

chmod 0644 "$LOGFILE"
