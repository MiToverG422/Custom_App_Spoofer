#!/system/bin/sh

ui_print " "
ui_print "  Custom App Spoofer"
ui_print "  Config-only build"
ui_print "  Requires a Zygisk provider on KernelSU/APatch, such as ZygiskNext/ReZygisk/NeoZygisk."
ui_print "  Includes LSPlant ART hooks for AppFeature rules. arm64 only."
ui_print "  Edit: /data/adb/modules/custom_app_spoofer/config/config.toml"
ui_print "  Log:  /data/adb/modules/custom_app_spoofer/logs/runtime.log"
ui_print " "

if [ ! -f "$MODPATH/zygisk/arm64-v8a.so" ]; then
  abort "Missing Zygisk libraries. Build the module zip before installing."
fi

if [ ! -f "$MODPATH/hooker.dex" ]; then
  abort "Missing hooker dex. Build the module zip before installing."
fi

mkdir -p "$MODPATH/config" "$MODPATH/logs"
touch "$MODPATH/logs/runtime.log"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644
set_perm_recursive "$MODPATH/logs" 0 0 0755 0644
set_perm "$MODPATH/customize.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/config/config.toml" 0 0 0644
set_perm "$MODPATH/logs/runtime.log" 0 0 0644
