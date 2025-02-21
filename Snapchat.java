package com.toyopagroup.picaboo;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BlockHook;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.NSData;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.snapchat.pb.Att;
import com.snapchat.pb.EncryptedData;
import com.sun.jna.Pointer;
import com.toyopagroup.picaboo.pb.AppleIv;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public abstract class Snapchat implements EmulatorConfigurator, ModuleListener, SnapchatApi, Closeable {

    public static final BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(64);

    protected final Emulator<?> emulator;
    protected final Module executable;
    protected final ObjC objc;
    protected final ObjcObject client;

    protected final String encryptClassName;
    protected final String encryptSelector;
    protected final String testSelector;

    protected final boolean debug;
    private final LoadedIpa loadedIpa;

    /**
     * @param className search AFHTTPClient
     */
    public Snapchat(File ipa, String className, String testSelector, String encryptSelector) {
        this(ipa, className, testSelector, encryptSelector, false, true);
    }

    public String getBundleVersion() {
        return loadedIpa.getBundleVersion();
    }

    public String getBackend() {
        return emulator.getBackend().getClass().getSimpleName();
    }

    public abstract long getAppVersion();

    @Override
    public String toString() {
        return emulator.getBackend().getClass().getSimpleName() + "_" + loadedIpa.getBundleIdentifier() + "_" + loadedIpa.getBundleVersion();
    }

    public Snapchat(File ipa, String className, String testSelector, String encryptSelector, boolean callFinishLaunchingWithOptions, boolean debug) {
        this.debug = debug;

        IpaLoader ipaLoader = createLoader(ipa);
        loadedIpa = ipaLoader.load(this);
        emulator = loadedIpa.getEmulator();
        executable = loadedIpa.getExecutable();

        objc = ObjC.getInstance(emulator);
        if (callFinishLaunchingWithOptions) {
            patch(Substrate.getInstance(emulator));
        }

        this.encryptClassName = className;
        this.testSelector = testSelector;
        this.encryptSelector = encryptSelector;

        loadedIpa.setCallFinishLaunchingWithOptions(callFinishLaunchingWithOptions);
        loadedIpa.callEntry();

        ObjcClass cClient = objc.lookUpClass(className);
        client = cClient == null ? null : cClient.callObjc("sharedSnapConnectClient");

        init();
    }

    protected final void testEncrypt(String[] args) throws DecoderException, InvalidProtocolBufferException {
        long start = System.currentTimeMillis();
        byte[] data = Hex.decodeHex(args[0].toCharArray());
        byte[] key = Hex.decodeHex(args[1].toCharArray());
        byte[] iv = Hex.decodeHex(args[2].toCharArray());
        byte[] result = encryptAesGcmDirect(data, key, iv);
        Inspector.inspect(result, "Test backend=" + emulator.getBackend() + ", offset=" + (System.currentTimeMillis() - start) + "ms\n" + Att.parseFrom(Arrays.copyOf(data, data.length - data[data.length - 1])));
    }

    protected IpaLoader createLoader(File ipa) {
        IpaLoader loader = new IpaLoader64(ipa, new File("target/rootfs/snapchat"));
        if (!debug) {
            loader.addBackendFactory(new DynarmicFactory(true));
        }
        return loader;
    }

    protected void init() {
    }

    protected final void dumpRequest(long start, ObjcClass cNSString, ObjcObject request) throws InvalidProtocolBufferException {
        ObjcObject uuidField = cNSString.callObjc("stringWithCString:encoding:","X-Snapchat-UUID",4);
        ObjcObject attField = cNSString.callObjc("stringWithCString:encoding:","x-snapchat-att",4);
        ObjcObject uuid = request.callObjc("valueForHTTPHeaderField:", uuidField);
        ObjcObject att = request.callObjc("valueForHTTPHeaderField:", attField);
        NSData body = NSData.create(request.callObjc("HTTPBody"));
        String value = att.getDescription();
        Inspector.inspect(body == null ? null : body.getBytes(), "X-Snapchat-UUID=" + uuid.getDescription() + ", x-snapchat-att=" + value + ", headers=" + request.callObjc("allHTTPHeaderFields").getDescription() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        byte[] data = Base64.decodeBase64(value);
        dumpEncryptedData(data);

        if (testKey != null && testAtt != null) {
            System.out.println("x-snapchat-att: " + generateAtt(testKey, testAtt));
            testAtt = null;
        }
    }

    protected void patch(ISubstrate substrate) {
        ObjcClass cSCNConfigConfigurationRegistry = objc.getClass("SCNConfigConfigurationRegistry");
        substrate.hookMessageEx(cSCNConfigConfigurationRegistry.getMeta(), objc.registerName("setCircumstanceEngine:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                if (debug) {
                    System.out.println("Patch [SCNConfigConfigurationRegistry setCircumstanceEngine]");
                }
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cSCManagedCapturePreviewLayerController = objc.getClass("SCManagedCapturePreviewLayerController");
        substrate.hookMessageEx(cSCManagedCapturePreviewLayerController.getMeta(), objc.registerName("sharedInstance"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                if (debug) {
                    System.out.println("Patch [SCManagedCapturePreviewLayerController sharedInstance]");
                }
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cSCQueuePerformer = objc.getClass("SCQueuePerformer");
        substrate.hookMessageEx(cSCQueuePerformer, objc.registerName("performAndWait:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                if (debug) {
                    System.out.println("Patch [SCQueuePerformer performAndWait]");
                }
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cSCInitializeNotificationProcessorsCommand = objc.getClass("SCInitializeNotificationProcessorsCommand");
        substrate.hookMessageEx(cSCInitializeNotificationProcessorsCommand, objc.registerName("execute"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                if (debug) {
                    System.out.println("Patch [SCInitializeNotificationProcessorsCommand execute]");
                }
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cSCScopeGraphEntryPointCommand = objc.getClass("SCScopeGraphEntryPointCommand");
        substrate.hookMessageEx(cSCScopeGraphEntryPointCommand, objc.registerName("execute"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                if (debug) {
                    System.out.println("Patch [SCScopeGraphEntryPointCommand execute]");
                }
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cGADMobileAds = objc.lookUpClass("GADMobileAds");
        if (cGADMobileAds != null) {
            substrate.hookMessageEx(cGADMobileAds, objc.registerName("disableAutomatedInAppPurchaseReporting"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                    if (debug) {
                        System.out.println("Patch [GADMobileAds disableAutomatedInAppPurchaseReporting]");
                    }
                    return HookStatus.LR(emulator, 0);
                }
            });
        }
    }

    public static void dumpEncryptedData(byte[] data) throws InvalidProtocolBufferException {
        EncryptedData encryptedData = EncryptedData.parseFrom(data);
        Inspector.inspect(encryptedData.getIv().toByteArray(), "EncryptedData.iv\n" + AppleIv.parseFrom(encryptedData.getIv()));
        Inspector.inspect(encryptedData.getData().toByteArray(), "EncryptedData.data");
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        emulator.getSyscallHandler().setVerbose(debug);
    }

    private long returnValue;

    protected final void traceReturnValueFunction(Emulator<?> emulator, long returnValue) {
        this.returnValue = returnValue;
        emulator.getMemory().addModuleListener(this);
    }

    @Override
    public final void onLoaded(Emulator<?> emulator, Module module) {
        if (!debug) {
            return;
        }
        if ("Snapchat".equals(module.name)) {
            emulator.attach().traceFunctionCall(module, new FunctionCallListener() {
                @Override
                public void onCall(Emulator<?> emulator, long callerAddress, long functionAddress) {
                }
                @Override
                public void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args) {
                    RegisterContext context = emulator.getContext();
                    if (context.getLongArg(0) == returnValue) {
                        emulator.attach().debug();
                    }
                }
            });
        }
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
        if (!debug) {
            return;
        }
        long encryptFunctionAddress = getEncryptFunctionAddress();
        if (encryptFunctionAddress != 0) {
            emulator.attach().addBreakPoint(encryptFunctionAddress, (emulator1, address) -> {
                RegisterContext context = emulator1.getContext();
                Pointer data = context.getPointerArg(3);
                int size = context.getIntArg(4);
                Pointer iv = context.getPointerArg(5);
                byte[] pbData = data.getByteArray(0, size);
                Inspector.inspect(pbData, "replace original data=" + data + ", size=" + size + ", iv=" + iv);

                try {
                    Att att = Att.parseFrom(Arrays.copyOf(pbData, size - pbData[size - 1] & 0xff));
                    System.out.println("replace original\n" + att);
                    checkAtt(att);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return true;
            });
        }
    }

    protected void checkAtt(Att att) {
        if (!"9A127".equals(att.getDeviceVersionBuild())) { // NOT unidbg
            return;
        }
        if ((byte) (att.getInstallJunk() & 0xff) != Checksum.calcField16(att.getInstallJunk() >> 8)) {
            throw new IllegalStateException("Verify checksum failed.");
        }
        if (att.getCsopsStatus() != 0x26007900) {
            throw new IllegalStateException("Invalid csopsStatus.");
        }
        if(att.getExecutableFileSize() != executable.getFileSize()) {
            throw new IllegalStateException("Invalid executable file size.");
        }
        if (att.getFixed0X2020() != 0x2020) {
            throw new IllegalStateException("Invalid fixed 0x2020.");
        }
    }

    protected static void traceEncryptFunction(Emulator<?> emulator, String ivHex, Module executable) {
        emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer iv = context.getPointerArg(5);
                int ivSize = context.getIntArg(6);
                if (ivSize == 0xc) {
                    try {
                        byte[] ivData = iv.getByteArray(0, ivSize);
                        Pointer addr = UnidbgPointer.pointer(emulator, address);
                        Inspector.inspect(ivData, "Block address=0x" + addr);
                        if (ivHex.equals(Hex.encodeHexString(ivData))) {
                            if (String.valueOf(addr).contains("Snapchat")) {
                                emulator.attach().debug();
                            }
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
        }, executable.base, executable.base + executable.size, emulator);
    }

    protected static void traceHashFunction(Emulator<?> emulator, String requestToken, Module executable) {
        emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                Pointer ptr = context.getPointerArg(1);
                int length = context.getIntArg(2);
                byte[] data;
                try {
                    if (length == requestToken.length() &&
                            new String((data = ptr.getByteArray(0, length))).equals(requestToken)) {
                        Pointer addr = UnidbgPointer.pointer(emulator, address);
                        Inspector.inspect(data, "Block address=" + addr);
                        if (String.valueOf(addr).contains("Snapchat")) {
                            emulator.attach().debug();
                        }
                    }
                } catch(Exception ignored) {}
            }
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
            }
        }, executable.base, executable.base + executable.size, emulator);
    }

    protected static void tracePBWriteVarFunction(Emulator<?> emulator, Module executable) {
        emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                int tag = context.getIntArg(1);
                long value = context.getLongArg(2);
                if (tag == 33 && value == 0x26007900) {
                    emulator.attach().debug();
                }
            }
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
            }
        }, executable.base, executable.base + executable.size, emulator);
    }

    protected static void tracePBWriteFixed64(Emulator<?> emulator, Module executable) {
        emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                int tag = context.getIntArg(1);
                long value = context.getLongArg(2);
                if (tag == 39 && value == 0x1011121314151617L) {
                    emulator.attach().debug();
                }
            }
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
            }
        }, executable.base, executable.base + executable.size, emulator);
    }

    protected abstract void test() throws Exception;

    protected final byte[] decrypt(String x_snapchat_att) throws InvalidProtocolBufferException {
        byte[] pbData = Base64.decodeBase64(x_snapchat_att);
        EncryptedData encryptedData = EncryptedData.parseFrom(pbData);
        byte[] iv = Arrays.copyOf(encryptedData.getIv().toByteArray(), 0xc);
        iv[0xb] = 1;
        byte[] encrypted = encryptedData.getData().toByteArray();
        byte[] key = Arrays.copyOf(encrypted, 0x10);
        byte[] data = Arrays.copyOfRange(encrypted, 0x10, encrypted.length - 0x10);

        byte[] result = encryptAesGcmDirect(data, key, iv);
        return Arrays.copyOf(result, result.length - 0x10);
    }

    @Override
    public final synchronized long calcExecutablePathHash(String executablePath) {
        try {
            Number hash = executable.callFunction(emulator, getEncryptExecutablePathFunctionAddress(), Hex.decodeHex("4acae5427dcdcc1e764c9ab9a337f5bc".toCharArray()), executablePath, executablePath.length());
            return hash.longValue();
        } catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    public long getExecutableFileSize() {
        return executable.getFileSize();
    }

    @Override
    public final AttResult generateAtt(byte[] key, com.toyopagroup.picaboo.pb.Att att) {
        if (key.length != 16) {
            throw new IllegalArgumentException();
        }

        AppleIv.Builder ivBuilder = AppleIv.newBuilder();
        ivBuilder.setA1(0xa);
        ivBuilder.setMagic(getIvMagic());
        ivBuilder.setIsAndroid(false);
        ivBuilder.setA4(false);
        byte[] ivData = ivBuilder.build().toByteArray();
        if (ivData.length != 0xb) {
            throw new IllegalStateException();
        }
        byte[] iv = Arrays.copyOf(ivData, 0xc);
        iv[0xb] = 1;

        byte[] attData = att.toByteArray();
        byte pad = (byte) (4 - attData.length % 4);
        byte[] data = new byte[attData.length + pad];
        System.arraycopy(attData, 0, data, 0, attData.length);
        for (int i = 0; i < pad; i++) {
            data[attData.length + i] = pad;
        }

        byte[] encryptedAesGcm = encryptAesGcmDirect(data, key, iv);
        byte[] encrypted = new byte[encryptedAesGcm.length + 16];
        System.arraycopy(key, 0, encrypted, 0, 16);
        System.arraycopy(encryptedAesGcm, 0, encrypted, 16, encryptedAesGcm.length);

        EncryptedData.Builder encryptedBuilder = EncryptedData.newBuilder();
        encryptedBuilder.setIv(ByteString.copyFrom(ivData));
        encryptedBuilder.setData(ByteString.copyFrom(encrypted));

        return new AttResult(att, Base64.encodeBase64URLSafeString(encryptedBuilder.build().toByteArray()));
    }

    protected abstract int getIvMagic();

    protected void doTestObjc() throws InvalidProtocolBufferException {
        long start = System.currentTimeMillis();
        ObjcClass cNSString = objc.getClass("NSString");
        ObjcClass cNSURL = objc.getClass("NSURL");
        ObjcObject method = cNSString.callObjc("stringWithCString:encoding:","POST",4);
        ObjcObject url = cNSString.callObjc("stringWithCString:encoding:","https://ms.sc-jpl.com/rpc/getMapTiles",4);
        ObjcClass cNSMutableDictionary = objc.getClass("NSMutableDictionary");
        ObjcObject parameters = cNSMutableDictionary.callObjc("dictionary");
        parameters.callObjc("setValue:forKey:",
                cNSString.callObjc("stringWithCString:encoding:","940ecd548b6100e86e4bfceaf8a7bc1425e74d8519a57a8679b40914dcc51deb",4),
                cNSString.callObjc("stringWithCString:encoding:","req_token",4));
        parameters.callObjc("setValue:forKey:",
                cNSString.callObjc("stringWithCString:encoding:","b8816cec-3b76-40f6-9275-26808d0c73f3",4),
                cNSString.callObjc("stringWithCString:encoding:","snapchat_user_id",4));
        parameters.callObjc("setValue:forKey:",
                cNSString.callObjc("stringWithCString:encoding:","1637222694992",4),
                cNSString.callObjc("stringWithCString:encoding:","timestamp",4));
        parameters.callObjc("setValue:forKey:",
                cNSString.callObjc("stringWithCString:encoding:","gbb2299",4),
                cNSString.callObjc("stringWithCString:encoding:","username",4));
        ObjcObject request = client.callObjc(testSelector, method, cNSURL.callObjc("URLWithString:", url), parameters, 1);
        dumpRequest(start, cNSString, request);
    }

    protected abstract long getEncryptFunctionAddress();
    protected abstract long getHashFunctionAddress();
    protected abstract long getEncryptExecutablePathFunctionAddress();

    protected final synchronized byte[] encryptAesGcmDirect(byte[] data, byte[] key, byte[] iv) {
        long encryptFunctionAddress = getEncryptFunctionAddress();
        if (encryptFunctionAddress == 0L) {
            throw new UnsupportedOperationException();
        }
        Memory memory = emulator.getMemory();
        MemoryBlock out = memory.malloc(data.length, false);
        out.getPointer().write(0, new byte[data.length], 0, data.length);
        MemoryBlock tag = memory.malloc(16, false);
        tag.getPointer().write(0, new byte[16], 0, 16);
        try {
            int ret = executable.callFunction(emulator, encryptFunctionAddress,
                    out.getPointer(), tag.getPointer(),
                    key, data, data.length, iv, iv.length, 0, 0).intValue();
            if (ret == -1) {
                throw new IllegalStateException("ret=" + ret);
            }
            byte[] encrypted = out.getPointer().getByteArray(0, data.length);
            byte[] tagData = tag.getPointer().getByteArray(0, 16);
            byte[] all = new byte[encrypted.length + tagData.length];
            System.arraycopy(encrypted, 0, all, 0, encrypted.length);
            System.arraycopy(tagData, 0, all, encrypted.length, tagData.length);
            return all;
        } finally {
            tag.free();
            out.free();
        }
    }

    private byte[] testKey;
    private com.toyopagroup.picaboo.pb.Att testAtt;

    protected void hookEncryptFunction() {
        ISubstrate substrate = Substrate.getInstance(emulator);
        substrate.hookFunction(getEncryptFunctionAddress(), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer key = context.getPointerArg(2);
                Pointer data = context.getPointerArg(3);
                int size = context.getIntArg(4);
                Pointer iv = context.getPointerArg(5);
                byte[] pbData = data.getByteArray(0, size);
                Inspector.inspect(pbData, "data=" + data + ", size=" + size + ", iv=" + iv);

                try {
                    Att att = Att.parseFrom(Arrays.copyOf(pbData, size - pbData[size - 1] & 0xff));
                    testKey = key.getByteArray(0, 16);
                    testAtt = com.toyopagroup.picaboo.pb.Att.parseFrom(att.toByteArray());
                    System.out.println(att);
                    checkAtt(att);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return super.onCall(emulator, context, originFunction);
            }
        });
    }

    @Override
    public void close() throws IOException {
        emulator.close();
    }
}
