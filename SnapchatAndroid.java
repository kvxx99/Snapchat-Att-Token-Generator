package com.snapchat.client;

import android.content.pm.ApplicationInfo;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.RandomFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import com.google.protobuf.InvalidProtocolBufferException;
import com.snapchat.client.client_attestation.ArgosClient;
import com.snapchat.client.client_attestation.ArgosMode;
import com.snapchat.client.client_attestation.ArgosPlatformBlizzardLogger;
import com.snapchat.client.client_attestation.Configuration;
import com.snapchat.client.client_attestation.PlatformClientAttestation;
import com.snapchat.client.client_attestation.PreLoginAttestationClient;
import com.snapchat.client.grpc.AuthContextDelegate;
import com.snapchat.client.grpc.ChannelType;
import com.snapchat.client.grpc.GrpcParameters;
import com.snapchat.client.shims.DispatchQueue;
import com.snapchat.client.unidbg.EGLModule;
import com.snapchat.client.unidbg.GLESv3Module;
import com.snapchat.client.unidbg.SnapchatProxyClassFactory;
import com.snapchat.client.unidbg.TraceListener;
import com.snapchat.pb.Att;
import com.sun.jna.Pointer;
import com.toyopagroup.picaboo.Snapchat;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

public class SnapchatAndroid implements IOResolver<AndroidFileIO> {

    public static void main(String[] args) throws Exception {
        SnapchatAndroid snapchat = new SnapchatAndroid(new File(FileUtils.getUserDirectory(), "Documents/Snapchat/com-snapchat-android-95605-60221937-79f14ea2552013e7cf0282c14eefa8d6.apk"), false);
//        snapchat.loadClient();
        snapchat.test();
    }

    private final List<TraceHook> traceHookList = new ArrayList<>();
    private UnidbgPointer out, tag;
    private byte[] pbData;

    private void test() throws Exception {
        if (preLoginAttestationClient != null) {
            System.out.println(preLoginAttestationClient.getAttestationHeaders("a", "path", true, "id"));
        }
        if (argosClient != null) {
            System.out.println(argosClient.getAttestationHeaders("b", "path", false, "id", ArgosMode.LEGACYONLY));
        }

        /*long start = System.currentTimeMillis();
        ByteArray array = bzq.callStaticJniMethodObject(emulator, "d(Ljava/lang/String;Ljava/lang/String;)[B",
                "token", "/v1/metrics");
        Inspector.inspect(array.getValue(), "Test1 offset=" + (System.currentTimeMillis() - start) + ", x-snapchat-att=" + Base64.encodeBase64String(array.getValue()));
        Snapchat.dumpEncryptedData(array.getValue());*/

//        emulator.attach().addBreakPoint(module, 0x26167);
//        emulator.traceWrite().setRedirect(new PrintStream("target/androidWrite.txt"));
//        emulator.traceRead().setRedirect(new PrintStream("target/androidRead.txt"));
//        emulator.attach().addBreakPoint(module, 0x000266D6);

        /*emulator.attach().addBreakPoint(module, 0x14f65, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer out = context.getPointerArg(0);
                if (out == null) {
                    return true;
                }
                UnidbgPointer tag = context.getPointerArg(1);
                UnidbgPointer key = context.getPointerArg(2);
                UnidbgPointer data = context.getPointerArg(3);
                int size = context.getIntArg(4);
                UnidbgPointer iv = context.getPointerArg(5);
                int ivSize = context.getIntArg(6);
                traceHookList.add(emulator.traceWrite(out.peer, out.peer + size - 1, new TraceListener("Trace Out ", out.peer)));
                traceHookList.add(emulator.traceWrite(tag.peer, tag.peer + 15, new TraceListener("Trace Tag ", tag.peer)));
                traceHookList.add(emulator.traceRead(key.peer, key.peer + 15, new TraceListener("Trace Key ", key.peer)));
                traceHookList.add(emulator.traceRead(data.peer, data.peer + size - 1, new TraceListener("Trace Data", data.peer)));
                traceHookList.add(emulator.traceRead(iv.peer, iv.peer + ivSize - 1, new TraceListener("Trace Iv  ", iv.peer)));
                return true;
            }
        });*/

        emulator.attach().addBreakPoint(module, 0x2c868, (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            out = context.getPointerArg(0);
            tag = context.getPointerArg(1);
            UnidbgPointer key = context.getPointerArg(2);
            UnidbgPointer data = context.getPointerArg(3);
            int size = context.getIntArg(4);
            UnidbgPointer iv = context.getPointerArg(5);
            int ivSize = context.getIntArg(6);

            byte[] fake = new byte[16];
            for (int i = 0; i < fake.length; i++) {
                fake[i] = (byte) (0x80 + i);
            }
            key.write(0, fake, 0, fake.length);

            pbData = data.getByteArray(0, size);
            byte[] ivData = iv.getByteArray(0, ivSize);
            byte[] keyData = key.getByteArray(0, 16);
            try {
                System.out.println(Att.parseFrom(Arrays.copyOf(pbData, pbData.length - pbData[pbData.length - 1] & 0xff)));
            } catch (InvalidProtocolBufferException e) {
                e.printStackTrace();
            }
            Inspector.inspect(pbData, "Before encryptSnapchat key=" + Hex.encodeHexString(keyData) + ", iv=" + Hex.encodeHexString(ivData) + ", data=" + data);
            data.write(0, new byte[size], 0, size);
            return true;
        });
        emulator.attach().addBreakPoint(module, 0x2c86b, (emulator, address) -> {
            byte[] outData = out.getByteArray(0, pbData.length);
            byte[] tagData = tag.getByteArray(0, 16);
            byte[] all = new byte[outData.length + tagData.length];
            System.arraycopy(outData, 0, all, 0, outData.length);
            System.arraycopy(tagData, 0, all, pbData.length, tagData.length);
            Inspector.inspect(all, "After encryptSnapchat");
            return true;
        });

        /*emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer iv = context.getPointerArg(5);
                int ivSize = context.getIntArg(6);
                if (ivSize == 0xc) {
                    try {
                        byte[] ivData = iv.getByteArray(0, ivSize);
                        Inspector.inspect(ivData, "Block address=0x" + UnidbgPointer.pointer(emulator, address));
                        if ("1800200015c20d0908080a01".equals(Hex.encodeHexString(ivData))) {
//                            emulator.attach().debug();
                        }
                    } catch(Exception ignored) {}
                }
            }
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
            }
        }, 1, 0, emulator);*/

        /*emulator.attach().addBreakPoint(module, 0x14f70, (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            UnidbgPointer sp = context.getStackPointer();

            {
                UnidbgPointer out_0x0_0 = sp.share(0x510, 4);
                traceHookList.add(emulator.traceRead(out_0x0_0.peer, out_0x0_0.peer + 3, new FixValueTrace("Trace out_0x0_0 ", out_0x0_0.peer, 0x262a64d5L)));
                traceHookList.add(emulator.traceWrite(out_0x0_0.peer, out_0x0_0.peer + 3, new FixValueTrace("Trace out_0x0_0 ", out_0x0_0.peer, 0x262a64d5L)));

                UnidbgPointer out_0x0_1 = sp.share(0x59c, 4);
                traceHookList.add(emulator.traceRead(out_0x0_1.peer, out_0x0_1.peer + 3, new FixValueTrace("Trace out_0x0_1 ", out_0x0_1.peer, 0x3020100L)));
                traceHookList.add(emulator.traceWrite(out_0x0_1.peer, out_0x0_1.peer + 3, new FixValueTrace("Trace out_0x0_1 ", out_0x0_1.peer, 0x3020100L)));

                UnidbgPointer out_0x0 = sp.share(0x660, 4);
                traceHookList.add(emulator.traceRead(out_0x0.peer, out_0x0.peer + 3, new FixValueTrace("Trace out_0x0 ", out_0x0.peer, 0x252865d5L)));
                traceHookList.add(emulator.traceWrite(out_0x0.peer, out_0x0.peer + 3, new FixValueTrace("Trace out_0x0 ", out_0x0.peer, 0x252865d5L)));
            }

            {
                UnidbgPointer out_0x4 = sp.share(0x65c, 4);
                traceHookList.add(emulator.traceRead(out_0x4.peer, out_0x4.peer + 3, new FixValueTrace("Trace out_0x4 ", out_0x4.peer, 0xd23031b5L)));
                traceHookList.add(emulator.traceWrite(out_0x4.peer, out_0x4.peer + 3, new FixValueTrace("Trace out_0x4 ", out_0x4.peer, 0xd23031b5L)));
            }

            {
                UnidbgPointer out_0x8 = sp.share(0x648, 4);
                traceHookList.add(emulator.traceRead(out_0x8.peer, out_0x8.peer + 3, new FixValueTrace("Trace out_0x8 ", out_0x8.peer, 0x7cc985f4L)));
                traceHookList.add(emulator.traceWrite(out_0x8.peer, out_0x8.peer + 3, new FixValueTrace("Trace out_0x8 ", out_0x8.peer, 0x7cc985f4L)));
            }

            {
                UnidbgPointer out_0xc = sp.share(0x634, 4);
                traceHookList.add(emulator.traceRead(out_0xc.peer, out_0xc.peer + 3, new FixValueTrace("Trace out_0xc ", out_0xc.peer, 0x9f78a360L)));
                traceHookList.add(emulator.traceWrite(out_0xc.peer, out_0xc.peer + 3, new FixValueTrace("Trace out_0xc ", out_0xc.peer, 0x9f78a360L)));
            }

            {
                UnidbgPointer iv_0x0 = sp.share(0xe0, 4);
                traceHookList.add(emulator.traceRead(iv_0x0.peer, iv_0x0.peer + 3, new FixValueTrace("Trace iv_0x0 ", iv_0x0.peer, 0xa080020L)));
                traceHookList.add(emulator.traceWrite(iv_0x0.peer, iv_0x0.peer + 3, new FixValueTrace("Trace iv_0x0 ", iv_0x0.peer, 0xa080020L)));
            }

            {
                UnidbgPointer iv_0x4 = sp.share(0x6b8, 4);
                traceHookList.add(emulator.traceRead(iv_0x4.peer, iv_0x4.peer + 3, new FixValueTrace("Trace iv_0x4 ", iv_0x4.peer, 0xc6150118L)));
                traceHookList.add(emulator.traceWrite(iv_0x4.peer, iv_0x4.peer + 3, new FixValueTrace("Trace iv_0x4 ", iv_0x4.peer, 0xc6150118L)));
            }

            {
                UnidbgPointer iv_0x8 = sp.share(0x540, 4);
                traceHookList.add(emulator.traceRead(iv_0x8.peer, iv_0x8.peer + 3, new FixValueTrace("Trace iv_0x8 ", iv_0x8.peer, 0x1d363cfL)));
                traceHookList.add(emulator.traceWrite(iv_0x8.peer, iv_0x8.peer + 3, new FixValueTrace("Trace iv_0x8 ", iv_0x8.peer, 0x1d363cfL)));
            }

            return true;
        });*/

        System.out.println("module=" + module + ", backend=" + emulator.getBackend());
        vm.setVerbose(true);
//        emulator.attach().addBreakPoint(module, 0x49247);

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.replace(module.base + 0x54e71, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer out = context.getPointerArg(0);
                Pointer data = context.getPointerArg(1);
                int size = context.getIntArg(2);
                context.push(out, data.getByteArray(0, size));
                return super.onCall(emulator, context, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                super.postCall(emulator, context);
                Pointer out = context.pop();
                byte[] data = context.pop();
                byte[] hash = out.getByteArray(0, 32);
                ByteBuffer buffer = ByteBuffer.wrap(hash);
                long value = buffer.getLong();
                BigInteger bigInteger = BigInteger.valueOf(value);
                bigInteger = bigInteger.compareTo(BigInteger.ZERO) < 0 ? bigInteger.add(Snapchat.TWO_COMPL_REF) : bigInteger;
                Inspector.inspect(data, "Hash256: 0x" + Long.toHexString(value) + ", value=" + bigInteger);
            }
        }, true);

        emulator.attach().run((DebugRunnable<Void>) args -> {
            Memory memory = emulator.getMemory();
            byte[] data = new byte[128];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) i;
            }
            byte[] iv = Hex.decodeHex("1800200015c20d0908080a01".toCharArray());
            byte[] key = Hex.decodeHex("808182838485868788898a8b8c8d8e8f".toCharArray());

            ByteArray array = cSnapchatJNI.callStaticJniMethodObject(emulator, "encrypt_gcm", data, key, iv);
            Inspector.inspect(array.getValue(), "SnapchatJNI");

            MemoryBlock dataBlock = memory.malloc(data.length, false);
            dataBlock.getPointer().write(0, data, 0, data.length);
            MemoryBlock ivBlock = memory.malloc(iv.length, false);
            ivBlock.getPointer().write(0, iv, 0, iv.length);
            MemoryBlock keyBlock = memory.malloc(key.length, false);
            keyBlock.getPointer().write(0, key, 0, key.length);

            MemoryBlock out = memory.malloc(data.length, false);
            out.getPointer().write(0, new byte[data.length], 0, data.length);
            MemoryBlock tag = memory.malloc(16, false);
            tag.getPointer().write(0, new byte[16], 0, 16);
            try {
                int ret = module.callFunction(emulator, 0x14f65,
                        out.getPointer(), tag.getPointer(),
                        keyBlock.getPointer(), dataBlock.getPointer(), data.length, ivBlock.getPointer(), iv.length).intValue();
                byte[] encrypted = out.getPointer().getByteArray(0, data.length);
                byte[] tagData = tag.getPointer().getByteArray(0, 16);
                byte[] all = new byte[encrypted.length + tagData.length];
                System.arraycopy(encrypted, 0, all, 0, encrypted.length);
                System.arraycopy(tagData, 0, all, encrypted.length, tagData.length);
                Inspector.inspect(all, "Encrypted ret=" + ret);
            } finally {
                tag.free();
                out.free();

                dataBlock.free();
                keyBlock.free();
                ivBlock.free();
            }
            for (Iterator<TraceHook> iterator = traceHookList.iterator(); iterator.hasNext(); ) {
                TraceHook hook = iterator.next();
                hook.stopTrace();
                iterator.remove();
            }
            doDev();
            canBreak = false;
            return null;
        });
    }

    private void doDev() throws InvalidProtocolBufferException {
        long start = System.currentTimeMillis();
        ByteArray array = bzq.callStaticJniMethodObject(emulator, "d(Ljava/lang/String;Ljava/lang/String;)[B",
                "9307435070f142f86e6f72e9faa87d6425ef4d84196bda85c9b40a14d2c517db", "/loq/register_v1");
        Inspector.inspect(array.getValue(), "Test2 offset=" + (System.currentTimeMillis() - start) + ", x-snapchat-att=" + Base64.encodeBase64String(array.getValue()));
        Snapchat.dumpEncryptedData(array.getValue());
    }

    private final File apkFile;
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass bzq;
    private final DvmClass cSnapchatJNI;

    private boolean canBreak;

    private SnapchatAndroid(File apkFile, boolean logging) {
        this.apkFile = apkFile;

        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .build();
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);
        emulator.getSyscallHandler().addIOResolver(this);
        emulator.getSyscallHandler().setVerbose(logging);
        SystemPropertyHook hook = new SystemPropertyHook(emulator);
        hook.setPropertyProvider(key -> {
            RegisterContext context = emulator.getContext();
            System.out.println("key=" + key + ", LR=" + context.getLRPointer());
            return null;
        });
        memory.addHookListener(hook);

        emulator.set(ApplicationInfo.APK_PATH_KEY, apkFile.getAbsolutePath());

        vm = emulator.createDalvikVM(apkFile);
        vm.setVerbose(logging);
        vm.setDvmClassFactory(new SnapchatProxyClassFactory());

        vm.addNotFoundClass("com/snap/opera/view/NewConcentricTimerView");
        vm.addNotFoundClass("com/snap/opera/view/CountdownTimerView");
        vm.addNotFoundClass("com/snapchat/android/LandingPageActivityV1");
        vm.addNotFoundClass("xposed/dummy/XResourcesSuperClass");

//        emulator.attach().addBreakPoint(0x400417D4);
//        emulator.traceRead(0xbfffdce4L, 0xbfffdce4L + 64); // processed request token
//        emulator.traceWrite(0x401ac000, 0x401ac000 + 224); // pb out data
//        emulator.traceWrite(0xbfffea70L, 0xbfffea70L + 7); // requestTokenHash
//        emulator.traceWrite(0xbfffe55cL, 0xbfffe55cL + 31); // tab1
//        emulator.traceWrite(0xbfffdde4L, 0xbfffdde4L + 31); // tab2
        /*emulator.attach().addBreakPoint(0x40049246, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                Arm32RegisterContext context = emulator.getContext();
                int r1 = context.getR1Int();
                Pointer r2 = context.getR2Pointer();
                System.out.println("r1=0x" + Long.toHexString(r1 & 0xffffffffL) + ", r2=" + r2);
                return true;
            }
        });*/
        emulator.attach().addBreakPoint(0x4005a8ba, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                Pointer tab1 = context.getPointerArg(0);
                int index = context.getIntArg(1);
                Pointer tab2 = context.getPointerArg(2);
                long i1 = tab1.getInt(index * 4L) & 0xffffffffL;
                long i2 = tab2.getInt(index * 4L) & 0xffffffffL;
                System.out.println("index=" + index + ", i1=0x" + Long.toHexString(i1) + ", i2=0x" + Long.toHexString(i2) + ", result=0x" + Long.toHexString((i1 + i2) & 0xffffffffL) + ", tab1=" + tab1 + ", tab2=" + tab2);
                return true;
            }
        });
        emulator.attach().addBreakPoint(0x400491EC, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                if (emulator.getContext().getIntArg(0) == 0x2b &&
                        canBreak) {
                    return false;
                }
                return true;
            }
        });
        emulator.attach().addBreakPoint(0x4004922C, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                Arm32RegisterContext context = emulator.getContext();
                int size = context.getR11Int();
                if (size > 0) {
                    UnidbgPointer sp = context.getStackPointer();
                    UnidbgPointer src = sp.getPointer(0x2c);
                    UnidbgPointer dest = sp.getPointer(0x28);
                    byte[] data = src.getByteArray(0, Math.min(128, size * 4));
                    Inspector.inspect(data, "memcpy size=" + size + ", src=" + src + ", dest=" + dest);
                }
                return true;
            }
        });
        emulator.attach().addBreakPoint(0x40055fb6, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                Arm32RegisterContext context = emulator.getContext();
                int r0 = context.getR0Int();
                if (0x39333037 == r0) {
                    canBreak = true;
                    return false;
                }
                return true;
            }
        });

        DalvikModule sc = vm.loadLibrary("scplugin", false);
        sc.callJNI_OnLoad(emulator);
        this.module = sc.getModule();

        bzq = vm.resolveClass("rfr/bzq");

        DalvikModule snapchat = vm.loadLibrary(new File("src/main/native/libs/armeabi-v7a/libsnapchat.so"), false);
        snapchat.callJNI_OnLoad(emulator);
        cSnapchatJNI = vm.resolveClass("com/snapchat/djinni/SnapchatJNI");

        Symbol aes_gcm_encrypt = snapchat.getModule().findSymbolByName("aes_gcm_encrypt", false);
        emulator.attach().addBreakPoint(aes_gcm_encrypt.getAddress(), (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            UnidbgPointer out = context.getPointerArg(0);
            UnidbgPointer data = context.getPointerArg(1);
            int size = context.getIntArg(2);
            UnidbgPointer key = context.getPointerArg(3);
            UnidbgPointer iv = context.getPointerArg(5);
            int ivSize = context.getIntArg(6);
            UnidbgPointer tag = context.getPointerArg(7);
            traceHookList.add(emulator.traceWrite(out.peer, out.peer + size - 1, new TraceListener("Trace aes_gcm_encrypt Out ", out.peer)));
            traceHookList.add(emulator.traceWrite(tag.peer, tag.peer + 15, new TraceListener("Trace aes_gcm_encrypt Tag ", tag.peer)));
            traceHookList.add(emulator.traceRead(key.peer, key.peer + 15, new TraceListener("Trace aes_gcm_encrypt Key ", key.peer)));
            traceHookList.add(emulator.traceRead(data.peer, data.peer + size - 1, new TraceListener("Trace aes_gcm_encrypt Data", data.peer)));
            traceHookList.add(emulator.traceRead(iv.peer, iv.peer + ivSize - 1, new TraceListener("Trace aes_gcm_encrypt Iv  ", iv.peer)));
            return true;
        });
    }

    private PreLoginAttestationClient preLoginAttestationClient;
    private ArgosClient argosClient;

    protected final void loadClient() {
        Memory memory = emulator.getMemory();
        new AndroidModule(emulator, vm).register(memory);
        new JniGraphics(emulator, vm).register(memory);
        new EGLModule(emulator).register(memory);
        new GLESv3Module(emulator).register(memory);

        DalvikModule dm = vm.loadLibrary("client", false);
        dm.callJNI_OnLoad(emulator);

        DvmObject<?> platformClientAttestation = ProxyDvmObject.createObject(vm, new PlatformClientAttestation());
        DvmObject<?> argosPlatformBlizzardLogger = ProxyDvmObject.createObject(vm, new ArgosPlatformBlizzardLogger());
        DvmClass cPreLoginAttestationClient = vm.resolveClass(PreLoginAttestationClient.class.getName().replace('.', '/'));
        DvmObject<?> obj = cPreLoginAttestationClient.callStaticJniMethodObject(emulator, "createInstance",
                platformClientAttestation, argosPlatformBlizzardLogger);
        this.preLoginAttestationClient = (PreLoginAttestationClient) obj.getValue();

        DvmClass cArgosClient = vm.resolveClass(ArgosClient.class.getName().replace('.', '/'));
        GrpcParameters parameters = new GrpcParameters("127.0.0.1", 0L, ChannelType.INSECURE, "uap", 0L, "rpp", 0L, "scck", true);
        DvmObject<?> configuration = ProxyDvmObject.createObject(vm, new Configuration(parameters, new HashMap<>()));
        DvmObject<?> authContextDelegate = ProxyDvmObject.createObject(vm, new AuthContextDelegate());
        DvmObject<?> dispatchQueue = ProxyDvmObject.createObject(vm, new DispatchQueue());
        obj = cArgosClient.callStaticJniMethodObject(emulator, "createInstance",
                platformClientAttestation, configuration, authContextDelegate, argosPlatformBlizzardLogger, dispatchQueue);
        this.argosClient = (ArgosClient) obj.getValue();
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if ("/proc/self/cmdline".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, vm.getPackageName().getBytes()));
        }
        if ("/proc/self/status".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, ("Name:\tnapchat.android\n" +
                    "State:\tS (sleeping)\n" +
                    "Tgid:\t18923\n" +
                    "Pid:\t18923\n" +
                    "PPid:\t640\n" +
                    "TracerPid:\t0\n" +
                    "Uid:\t10072\t10072\t10072\t10072\n" +
                    "Gid:\t10072\t10072\t10072\t10072\n" +
                    "Ngid:\t0\n" +
                    "FDSize:\t128\n" +
                    "Groups:\t3001 3002 3003 9997 50072\n" +
                    "VmPeak:\t 1951120 kB\n" +
                    "VmSize:\t 1947064 kB\n" +
                    "VmLck:\t       0 kB\n" +
                    "VmPin:\t       0 kB\n" +
                    "VmHWM:\t  144984 kB\n" +
                    "VmRSS:\t  144348 kB\n" +
                    "VmData:\t  225348 kB\n" +
                    "VmStk:\t    8196 kB\n" +
                    "VmExe:\t      52 kB\n" +
                    "VmLib:\t  140868 kB\n" +
                    "VmPTE:\t    1008 kB\n" +
                    "VmSwap:\t       0 kB\n" +
                    "Threads:\t58\n" +
                    "SigQ:\t0/14024\n" +
                    "SigPnd:\t0000000000000000\n" +
                    "ShdPnd:\t0000000000000000\n" +
                    "SigBlk:\t0000000000001204\n" +
                    "SigIgn:\t0000000000000000\n" +
                    "SigCgt:\t20000002000084f8\n" +
                    "CapInh:\t0000000000000000\n" +
                    "CapPrm:\t0000000000000000\n" +
                    "CapEff:\t0000000000000000\n" +
                    "CapBnd:\t0000000000000000\n" +
                    "Seccomp:\t0\n" +
                    "Cpus_allowed:\tf\n" +
                    "Cpus_allowed_list:\t0-3\n" +
                    "Mems_allowed:\t1\n" +
                    "Mems_allowed_list:\t0\n" +
                    "voluntary_ctxt_switches:\t526\n" +
                    "nonvoluntary_ctxt_switches:\t206\n").getBytes()));
        }
        if (apkFile.getAbsolutePath().equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, apkFile, pathname));
        }
        if (pathname.endsWith("/lib/armeabi-v7a/libscplugin.so")) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, Objects.requireNonNull(vm.unzip("lib/armeabi-v7a/libscplugin.so"))));
        }
        if (pathname.equals("/proc/mounts")) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, ("rootfs / rootfs ro,seclabel,relatime 0 0\n" +
                    "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0\n" +
                    "devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0\n" +
                    "proc /proc proc rw,relatime 0 0\n" +
                    "sysfs /sys sysfs rw,seclabel,relatime 0 0\n" +
                    "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n" +
                    "debugfs /sys/kernel/debug debugfs rw,relatime 0 0\n" +
                    "none /acct cgroup rw,relatime,cpuacct 0 0\n" +
                    "none /sys/fs/cgroup tmpfs rw,seclabel,relatime,mode=750,gid=1000 0 0\n" +
                    "tmpfs /mnt/asec tmpfs rw,seclabel,relatime,mode=755,gid=1000 0 0\n" +
                    "tmpfs /mnt/obb tmpfs rw,seclabel,relatime,mode=755,gid=1000 0 0\n" +
                    "tmpfs /mnt/fuse tmpfs rw,seclabel,relatime,mode=775,gid=1000 0 0\n" +
                    "none /dev/cpuctl cgroup rw,relatime,cpu 0 0\n" +
                    "/dev/block/platform/msm_sdcc.1/by-name/system /system ext4 ro,seclabel,relatime,data=ordered 0 0\n" +
                    "/dev/block/platform/msm_sdcc.1/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,errors=panic,data=ordered 0 0\n" +
                    "/dev/block/platform/msm_sdcc.1/by-name/cache /cache ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,errors=panic,data=ordered 0 0\n" +
                    "/dev/block/platform/msm_sdcc.1/by-name/persist /persist ext4 rw,seclabel,nosuid,nodev,relatime,nomblk_io_submit,nodelalloc,errors=panic,data=ordered 0 0\n" +
                    "/dev/block/platform/msm_sdcc.1/by-name/modem /firmware vfat ro,relatime,uid=1000,gid=1000,fmask=0337,dmask=0227,codepage=cp437,iocharset=iso8859-1,shortname=lower,errors=remount-ro 0 0\n" +
                    "/dev/fuse /mnt/shell/emulated fuse rw,nosuid,nodev,relatime,user_id=1023,group_id=1023,default_permissions,allow_other 0 0\n\n").getBytes(StandardCharsets.UTF_8)));
        }
        if ("/proc/self/mounts".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, ("rootfs / rootfs rw,seclabel 0 0\n" +
                    "binder /dev/binder ext4 ro,seclabel,relatime,data=ordered 0 0\n" +
                    "/dev/root / ext4 ro,seclabel,relatime,data=ordered 0 0\n" +
                    "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=1897816k,nr_inodes=474454,mode=755 0 0\n" +
                    "devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0\n" +
                    "none /dev/stune cgroup rw,relatime,schedtune 0 0\n" +
                    "none /dev/cpuctl cgroup rw,relatime,cpu 0 0\n" +
                    "none /dev/cpuset cgroup rw,relatime,cpuset,noprefix,release_agent=/sbin/cpuset_release_agent 0 0\n" +
                    "adb /dev/usb-ffs/adb functionfs rw,relatime 0 0\n" +
                    "proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0\n" +
                    "sysfs /sys sysfs rw,seclabel,relatime 0 0\n" +
                    "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n" +
                    "debugfs /sys/kernel/debug debugfs rw,seclabel,relatime 0 0\n" +
                    "pstore /sys/fs/pstore pstore rw,seclabel,relatime 0 0\n" +
                    "none /acct cgroup rw,relatime,cpuacct 0 0\n" +
                    "tmpfs /mnt tmpfs rw,seclabel,relatime,size=1897816k,nr_inodes=474454,mode=755,gid=1000 0 0\n" +
                    "/data/media /mnt/runtime/default/emulated sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=1015,multiuser,mask=6 0 0\n" +
                    "/data/media /mnt/runtime/read/emulated sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=9997,multiuser,mask=23 0 0\n" +
                    "/data/media /mnt/runtime/write/emulated sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=9997,multiuser,mask=7 0 0\n" +
                    "none /config configfs rw,relatime 0 0\n" +
                    "/dev/block/bootdevice/by-name/vendor_b /vendor ext4 ro,seclabel,relatime,discard,data=ordered 0 0\n" +
                    "/dev/block/bootdevice/by-name/modem_b /firmware/radio vfat ro,context=u:object_r:firmware_file:s0,relatime,uid=1000,fmask=0337,dmask=0227,codepage=437,iocharset=iso8859-1,shortname=lower,errors=remount-ro 0 0\n" +
                    "/dev/block/bootdevice/by-name/persist /persist ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0\n" +
                    "/dev/block/bootdevice/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,data=ordered 0 0\n" +
                    "tmpfs /storage tmpfs rw,seclabel,relatime,size=1897816k,nr_inodes=474454,mode=755,gid=1000 0 0\n" +
                    "/data/media /storage/emulated sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=9997,multiuser,mask=7 0 0\n" +
                    "tmpfs /storage/self tmpfs rw,seclabel,relatime,size=1897816k,nr_inodes=474454,mode=755,gid=1000 0 0\n").getBytes()));
        }
        if ("/dev/urandom".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new RandomFileIO(emulator, pathname) {
                @Override
                protected void randBytes(byte[] buf) {
                    for (int i = 0; i < buf.length; i++) {
                        buf[i] = (byte) i;
                    }
                }
            });
        }
        return null;
    }

}
