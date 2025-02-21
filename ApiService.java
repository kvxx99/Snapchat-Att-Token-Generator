package com.snapchat.spring;

import com.alibaba.fastjson.JSONObject;
import com.toyopagroup.picaboo.AttResult;
import com.toyopagroup.picaboo.Checksum;
import com.toyopagroup.picaboo.Snapchat;
import com.toyopagroup.picaboo.Snapchat_11_63_0;
import com.toyopagroup.picaboo.pb.Att;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

@Controller
@RequestMapping("/api")
public class ApiService implements InitializingBean, DisposableBean {

    private static final Log log = LogFactory.getLog(ApiService.class);

    private Snapchat snapchat;

    @Override
    public void destroy() throws Exception {
        snapchat.close();
    }

    @Override
    public void afterPropertiesSet() {
        long start = System.currentTimeMillis();
        snapchat = new Snapchat_11_63_0(new File(FileUtils.getUserDirectory(), "Documents/Snapchat/app/Snapchat_11_63_0.ipa"), false);
        log.info("load " + snapchat + ": " + (System.currentTimeMillis() - start) + "ms");
    }

    /**
     * /api/generateMsg?deviceModel=iPhone6,2&deviceVersionBuild=9A127&timestampStart=1643720017775&timestampCurrent=1643721350720&sequenceId=6617262763463061208&sequenceNumber=7&sequenceNumberTwo=7&installJunk=8106755191704838089&presses=0&requestPath=/scauth/login&requestToken=9307435070f142f86e6f72e9faa87d6425ef4d84196bda85c9b40a14d2c517db&cdHash=9307435070f142f86e6f72e9faa87d6425ef4d84196bda85c9b40a14d2c517db
     */
    @RequestMapping(value = "/generateMsg")
    public String generateMsg(Model model, @RequestParam(value = "deviceModel") String deviceModel,
                              @RequestParam(value = "deviceVersionBuild") String deviceVersionBuild,
                              @RequestParam(value = "timestampStart") long timestampStart,
                              @RequestParam(value = "timestampCurrent") long timestampCurrent,
                              @RequestParam(value = "sequenceId") long sequenceId,
                              @RequestParam(value = "sequenceNumber") int sequenceNumber,
                              @RequestParam(value = "sequenceNumberTwo") int sequenceNumberTwo,
                              @RequestParam(value = "installJunk") long installJunk,
                              @RequestParam(value = "presses") int presses,
                              @RequestParam(value = "requestPath") String requestPath,
                              @RequestParam(value = "requestToken") String requestToken,
                              @RequestParam(value = "cdHash") String cdHash) {
        try {
            byte[] key = new SecureRandom().generateSeed(16);

            long installSeed = installJunk >> 8;
            int b = Checksum.calcField16(installSeed) & 0xff;
            UUID uuid = UUID.nameUUIDFromBytes((installSeed + "_Application").getBytes(StandardCharsets.UTF_8));
            String executablePath = "/var/containers/Bundle/Application/" + uuid.toString().toUpperCase() + "/Snapchat.app/Snapchat";

            Att.Builder builder = createBuilder(requestPath, timestampCurrent, deviceModel, deviceVersionBuild,
                    timestampStart, sequenceNumber, sequenceNumberTwo, sequenceId, (installSeed << 8) | b, executablePath,
                    presses, requestToken, cdHash);

            AttResult result = snapchat.generateAtt(key, builder.build());
            model.addAttribute("att", "x-snapchat-att: " + result.getEncrypted());
            model.addAttribute("msg", result.getAtt().toString());
            model.addAttribute("executablePath", "Executable path: " + executablePath);
            return "/msg";
        } catch (DecoderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Att.Builder createBuilder(String requestPath, long timestampCurrent, String deviceModel, String deviceVersionBuild,
                             long timestampStart, long sequenceNumber, long sequenceNumberTwo, long sequenceId, long installJunk, String executablePath,
                             int presses, String requestToken, String cdHash) throws DecoderException {
        Att.Builder builder = Att.newBuilder();
        builder.setIsAuthLogin("/scauth/login".equals(requestPath));
        builder.setTimestampCurrent(timestampCurrent);
        builder.setFlags(0x1);
        builder.setDeviceModel(deviceModel);
        builder.setDeviceVersionBuild(deviceVersionBuild);
        builder.setTimestampStart(timestampStart);
        builder.setSequenceNumber(sequenceNumber);
        builder.setSequenceNumberTwo(sequenceNumberTwo);
        builder.setSequenceId(sequenceId);
        builder.setInstallJunk(installJunk);
        builder.setAppVersion(snapchat.getAppVersion());
        builder.setExecutableFileSize(snapchat.getExecutableFileSize());
        builder.setFixed0X2020(0x2020);
        builder.setExecutablePathHash(snapchat.calcExecutablePathHash(executablePath));
        builder.setCsopsStatus(0x26007900);
        builder.setPresses(presses);
        builder.setRequestTokenHash(Checksum.calcHash256(requestToken));
        builder.setCdHash(Checksum.bigEndianLong(Hex.decodeHex(cdHash.toCharArray())));
        builder.setRequestPathHash(Checksum.calcHash256(requestPath));
        builder.setBundleIdentifierHash(Checksum.calcHash256("com.toyopagroup.picaboo,LJX9PEWK8U"));
        return builder;
    }

    private int count;

    /**
     * /api/generate?deviceModel=iPhone6,2&deviceVersionBuild=9A127&timestampStart=1643720017775&timestampCurrent=1643721350720&sequenceId=6617262763463061208&sequenceNumber=7&sequenceNumberTwo=7&installJunk=8106755191704838089&presses=0&requestPath=/scauth/login&requestToken=9307435070f142f86e6f72e9faa87d6425ef4d84196bda85c9b40a14d2c517db&cdHash=9307435070f142f86e6f72e9faa87d6425ef4d84196bda85c9b40a14d2c517db
     */
    @RequestMapping(value = "/generate", method = RequestMethod.GET, produces = {"application/json;charset=UTF-8"})
    public ResponseEntity<JSONObject> generate(@RequestParam(value = "deviceModel") String deviceModel,
                                           @RequestParam(value = "deviceVersionBuild") String deviceVersionBuild,
                                           @RequestParam(value = "timestampStart") long timestampStart,
                                           @RequestParam(value = "timestampCurrent") long timestampCurrent,
                                           @RequestParam(value = "sequenceId") long sequenceId,
                                           @RequestParam(value = "sequenceNumber") int sequenceNumber,
                                           @RequestParam(value = "sequenceNumberTwo") int sequenceNumberTwo,
                                           @RequestParam(value = "installJunk") long installJunk,
                                           @RequestParam(value = "presses") int presses,
                                           @RequestParam(value = "requestPath") String requestPath,
                                           @RequestParam(value = "requestToken") String requestToken,
                                           @RequestParam(value = "cdHash") String cdHash) {
        try {
            long start = System.currentTimeMillis();
            byte[] key = new SecureRandom().generateSeed(16);

            long installSeed = installJunk >> 8;
            int b = Checksum.calcField16(installSeed) & 0xff;
            UUID uuid = UUID.nameUUIDFromBytes((installSeed + "_Application").getBytes(StandardCharsets.UTF_8));
            String executablePath = "/var/containers/Bundle/Application/" + uuid.toString().toUpperCase() + "/Snapchat.app/Snapchat";

            Att.Builder builder = createBuilder(requestPath, timestampCurrent, deviceModel, deviceVersionBuild,
                    timestampStart, sequenceNumber, sequenceNumberTwo, sequenceId, (installSeed << 8) | b, executablePath,
                    presses, requestToken, cdHash);

            AttResult result = snapchat.generateAtt(key, builder.build());
            JSONObject obj = new JSONObject(8);
            obj.put("code", 0);
            obj.put("att", result.getEncrypted());
            obj.put("pbMsg", result.getAtt().toByteArray());
            obj.put("version", snapchat.getBundleVersion());
            obj.put("executablePath", executablePath);
            obj.put("elapsedTimeInMillis", System.currentTimeMillis() - start);
            obj.put("backend", snapchat.getBackend());
            obj.put("count", ++count);
            return ResponseEntity.ok(obj);
        } catch (DecoderException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
