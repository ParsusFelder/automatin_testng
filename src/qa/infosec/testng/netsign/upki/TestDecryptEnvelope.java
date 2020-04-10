package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestDecryptEnvelope
 * @date 2020-03-02 18:05
 * @Description: 解密数字信封
 * <p>用例覆盖点：</p>
 * <p>1）解密数字信封（decryptEnvelope），解密使用证书DN</p>
 * <p>2）解密数字信封（decryptEnvelope），解密使用证书SN</p>
 * <p>3）解密数字信封（decryptEnvelope），解密使用证书bankcode</p>
 * <p>4）解密数字信封（decryptEnvelope），密文为null或空字符</p>
 * <p>5）解密数字信封（decryptEnvelope），DN/SN/BankCode为null</p>
 * <p>6）解密数字信封（decryptEnvelope），DN/SN/BankCode为空字符</p>
 * <p>7）解密数字信封（decryptEnvelope），DN与加密使用证书不匹配</p>
 * <p>8）解密数字信封（decryptEnvelope），密文篡改</p>
 */
@Test(groups = "abcjew.decryptenvelope")
public class TestDecryptEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");

        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
    }

    /**
     * 解密数字信封，解密使用证书DN
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_01(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），解密使用证书DN");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertDN);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，解密使用证书SN
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_02(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），解密使用证书SN");

        String[] split = str.split("%");
        String sCertSN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertSN, sAlg, null);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertSN);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，解密使用证书bankcode
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "all-symmalg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_03(String sAlg, String bankcode) {
        System.out.println("解密数字信封（decryptEnvelope），解密使用证书bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, bankcode, sAlg, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203) {
                    Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作数字信封（encryptEnvelope）:部分证书的bankcode做业务失败");
                return;
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        if (upkiResult.getResults() != null) {
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            try {
                upkiResult1 = agent.decryptEnvelope(enc_text, bankcode);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            } catch (Exception e) {
                Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * 解密数字信封，密文为null或空字符
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_04(String enc_text) {
        System.out.println("解密数字信封（decryptEnvelope），密文为null或空字符");

        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        UpkiResult upkiResult = null;
        // 解密数字信封
        try {
            upkiResult = agent.decryptEnvelope(enc_text, sCertDN);
            if (upkiResult.getReturnCode() != -100212 && -1011 != upkiResult.getReturnCode()) {
                Assert.fail("解密数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，DN/SN/BankCode为null
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_05(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），DN/SN/BankCode为null");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, null);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("解密数字信封（decryptEnvelope）：DN为null,可以解密成功");
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，DN/SN/BankCode为空
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_06(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），DN/SN/BankCode为空字符");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, "");
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("解密数字信封（decryptEnvelope）：DN为空,可以解密成功");
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，DN与加密使用证书不匹配
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_07(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），DN与加密使用证书不匹配");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, "CN=123");
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("解密数字信封（decryptEnvelope）：DN与加密时使用证书不匹配,能够解密成功");
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 解密数字信封，密文篡改
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_08(String sAlg, String str) {
        System.out.println("解密数字信封（decryptEnvelope），密文篡改");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // 制作数字信封
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
        // 解密数字信封
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                StringBuilder stringBuilder = new StringBuilder(enc_text);
                stringBuilder.replace(5, 10, "abcdef");
                enc_text = new String(stringBuilder);
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertDN);
                if (upkiResult1.getReturnCode() != -100212) {
                    Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("解密数字信封失败：" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }
}
