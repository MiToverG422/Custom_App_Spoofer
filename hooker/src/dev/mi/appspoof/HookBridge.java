package dev.mi.appspoof;

public final class HookBridge {
    private final int id;

    public HookBridge(int id) {
        this.id = id;
    }

    public Object callback(Object[] args) {
        return dispatch(id, args);
    }

    private static native Object dispatch(int id, Object[] args);
}
