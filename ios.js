var encodeHexString = function (buffer) {
    var array = new Uint8Array(buffer);
    var str = "";
    for(var i = 0; i < array.length; i++) {
        var c = array[i].toString(16);
        if (c.length <= 1) {
            str += "0";
        }
        str += c;
    }
    return str;
};

var requiredCodeSigning = Process.codeSigningPolicy === "required";

var onExecutableModule = function (module) {
    var bundle = ObjC.classes.NSBundle.mainBundle();
    var directory = bundle.infoDictionary();
    var version = directory.objectForKey_("CFBundleShortVersionString");
    console.log("Snapchat version is: " + version);

    var encryptAesGcm, hashFunction;
    var cClient, sign, signV2;
    if (version.toString() === "11.52.0") {
        if (!requiredCodeSigning) {
            encryptAesGcm = module.base.add(0x6eac44);
            Interceptor.attach(encryptAesGcm, {
                onEnter: function (args) {
                    this.out = args[0];
                    this.tag = args[1];
                    this.key = Memory.readByteArray(args[2], 16);
                    this.length = args[4].toInt32();
                    this.data = Memory.readByteArray(args[3], this.length);
                    this.iv = Memory.readByteArray(args[5], args[6].toInt32());
                },
                onLeave: function (ret) {
                    var out = Memory.readByteArray(this.out, this.length);
                    var tag = Memory.readByteArray(this.tag, 16);
                    console.log("encryptAesGcm data=" + encodeHexString(this.data) + ", key=" + encodeHexString(this.key) + ", iv=" + encodeHexString(this.iv) + ", out=" + encodeHexString(out) + ", tag=" + encodeHexString(tag));
                }
            });
            hashFunction = module.base.add(0x6c87c8);
            Interceptor.attach(hashFunction, {
                onEnter: function (args) {
                    this.out = args[0];
                    this.data = Memory.readByteArray(args[1], args[2].toInt32());
                },
                onLeave: function (ret) {
                    var out = Memory.readByteArray(this.out, 32);
                    console.log("hashFunction data=" + encodeHexString(this.data) + ", out=" + encodeHexString(out));
                }
            });

            cClient = ObjC.classes["b794290b839"];
            {
                sign = cClient["- fdd7227e433e5a0ca:9bc:56f267c41f:1ed4d1035fcd3:"];
                if (sign) {
                    Interceptor.attach(sign.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.url = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                            this.with_x_snapchat_att = args[5];
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            console.log("generate x-snapchat-att: method=" + this.method + ", url=" + this.url + ", parameters=" + this.parameters + ", with_x_snapchat_att=" + this.with_x_snapchat_att + ", headers=" + request.allHTTPHeaderFields());
                        }
                    });
                    console.log("Hook client sign");
                } else {
                    console.log("Hook client sign failed");
                }
            }
            {
                signV2 = cClient["- 267a86f59620fcdcf:5206:71b6266d24:"];
                if (signV2) {
                    Interceptor.attach(signV2.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.path = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            console.log("generate x-snapchat-att V2: method=" + this.method + ", path=" + this.path + ", parameters=" + this.parameters + ", headers=" + request.allHTTPHeaderFields());
                        }
                    });
                    console.log("Hook client signV2");
                } else {
                    console.log("Hook client signV2 failed");
                }
            }
        }
    }

    if (version.toString() === "11.54.2") {
        if (!requiredCodeSigning) {
            encryptAesGcm = module.base.add(0xa0a4f0);
            Interceptor.attach(encryptAesGcm, {
                onEnter: function (args) {
                    this.out = args[0];
                    this.tag = args[1];
                    this.key = Memory.readByteArray(args[2], 16);
                    this.length = args[4].toInt32();
                    this.data = Memory.readByteArray(args[3], this.length);
                    this.iv = Memory.readByteArray(args[5], args[6].toInt32());
                },
                onLeave: function (ret) {
                    var out = Memory.readByteArray(this.out, this.length);
                    var tag = Memory.readByteArray(this.tag, 16);
                    console.log("encryptAesGcm data=" + encodeHexString(this.data) + ", key=" + encodeHexString(this.key) + ", iv=" + encodeHexString(this.iv) + ", out=" + encodeHexString(out) + ", tag=" + encodeHexString(tag));
                }
            });

            cClient = ObjC.classes["05572403107"];
            {
                sign = cClient["- 8a777b05df97b8c3b:c75:944e3b5e7b:a4badfcae0a1e:"];
                if (sign) {
                    Interceptor.attach(sign.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.url = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                            this.with_x_snapchat_att = args[5];
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            console.log("generate x-snapchat-att: method=" + this.method + ", url=" + this.url + ", parameters=" + this.parameters + ", with_x_snapchat_att=" + this.with_x_snapchat_att + ", headers=" + request.allHTTPHeaderFields());
                        }
                    });
                    console.log("Hook client sign");
                } else {
                    console.log("Hook client sign failed");
                }
            }
            {
                signV2 = cClient["- 1810bf309e15be4de:e169:6a6fcc5a8f:"];
                if (signV2) {
                    Interceptor.attach(signV2.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.path = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            console.log("generate x-snapchat-att V2: method=" + this.method + ", path=" + this.path + ", parameters=" + this.parameters + ", headers=" + request.allHTTPHeaderFields());
                        }
                    });
                    console.log("Hook client signV2");
                } else {
                    console.log("Hook client signV2 failed");
                }
            }
        }
    }

    if (version.toString() === "11.63.0") {
        if (!requiredCodeSigning) {
            encryptAesGcm = module.base.add(0x67b360);
            Interceptor.attach(encryptAesGcm, {
                onEnter: function (args) {
                    this.out = args[0];
                    this.tag = args[1];
                    this.key = Memory.readByteArray(args[2], 16);
                    this.length = args[4].toInt32();
                    this.data = Memory.readByteArray(args[3], this.length);
                    this.iv = Memory.readByteArray(args[5], args[6].toInt32());
                },
                onLeave: function (ret) {
                    var out = Memory.readByteArray(this.out, this.length);
                    var tag = Memory.readByteArray(this.tag, 16);
                    console.log("encryptAesGcm data=" + encodeHexString(this.data) + ", key=" + encodeHexString(this.key) + ", iv=" + encodeHexString(this.iv) + ", out=" + encodeHexString(out) + ", tag=" + encodeHexString(tag));
                }
            });

            cClient = ObjC.classes["b3e77fb9d6e"];
            {
                sign = cClient["- 2387af78982688701:a17:5b3ea7aee0:fddee9bb14eaa:"];
                if (sign) {
                    Interceptor.attach(sign.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.url = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                            this.with_x_snapchat_att = args[5];
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            console.log("generate x-snapchat-att: method=" + this.method + ", url=" + this.url + ", parameters=" + this.parameters + ", with_x_snapchat_att=" + this.with_x_snapchat_att + ", headers=" + request.allHTTPHeaderFields());
                        }
                    });
                    console.log("Hook client sign");
                } else {
                    console.log("Hook client sign failed");
                }
            }
            {
                signV2 = cClient["- 47d06ad1055f4c0f6:4396:16a5d27af7:"];
                if (signV2) {
                    Interceptor.attach(signV2.implementation, {
                        onEnter: function (args) {
                            this.method = new ObjC.Object(args[2]);
                            this.path = new ObjC.Object(args[3]);
                            this.parameters = new ObjC.Object(args[4]);
                        },
                        onLeave: function (ret) {
                            var request = new ObjC.Object(ret);
                            var body = request.HTTPBody();
                            console.log("generate x-snapchat-att V2: method=" + this.method + ", path=" + this.path + ", parameters=" + this.parameters + ", headers=" + request.allHTTPHeaderFields() + ", body=" + body.bytes().readUtf8String(body.length()));
                        }
                    });
                    console.log("Hook client signV2");
                } else {
                    console.log("Hook client signV2 failed");
                }
            }
        }
    }
}

Process.enumerateModules({
    onMatch: function (module) {
        if (module.name === 'Snapchat') {
            console.log(JSON.stringify(module));
            onExecutableModule(module);
            return "stop";
        } else {
            console.log(JSON.stringify(module));
        }
    },
    onComplete: function () {
        console.log("enumerateModules completed");
    }
});
