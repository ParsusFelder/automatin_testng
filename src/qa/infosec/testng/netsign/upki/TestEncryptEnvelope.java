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
 * @ClassName: TestEncryptEnvelope
 * @date 2020-03-02 18:05
 * @Description: 制作数字信封
 * <p>用例覆盖点：</p>
 * <p>1）制作数字信封，证书DN与证书Base64信息匹配，对称算法为DES/3DES/RC2/RC4/SM4/AES</p>
 * <p>2）制作数字信封，证书DN与证书Base64信息匹配，对称算法为des/3des/rc2/rc4/sm4/aes</p>
 * <p>3）制作数字信封，仅使用DN</p>
 * <p>4）制作数字信封，仅使用SN</p>
 * <p>5）制作数字信封，仅使用bankcode</p>
 * <p>6）制作数字信封，DN/SN/bankcode为空</p>
 * <p>7）制作数字信封，DN/SN/bankcode为null</p>
 * <p>8）制作数字信封，DN/SN/bankcode与Base64信息均为空或null</p>
 * <p>9）制作数字信封，对称算法为空或null</p>
 */
@Test(groups = "abcjew.encryptenvelope")
public class TestEncryptEnvelope {
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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath, ParameterUtil.localdetailpath);
    }

    /**
     * 制作数字信封，证书DN与Base64信息匹配
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_01(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，证书DN与Base64信息匹配
     *
     * @param sAlg 对称算法为des/3des/rc2/rc4/sm4/aes
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_02(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg.toLowerCase(), sPublicKey);
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("制作数字信封（EncryptEnvelope）：对称加密算法不支持小写输入");
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，仅使用DN
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_03(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope  DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, null);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，仅使用SN
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_04(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope  SN Normal");
        String[] split = str.split("%");
        String sCertSN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertSN, sAlg, null);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，仅使用bankcode
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "all-symmalg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_05(String sAlg, String bankcode) {
        System.out.println("Test ABCJEW EncryptEnvelope  BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, bankcode, sAlg, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203) {
                    Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作数字信封（encryptEnvelope）:部分证书的bankcode做业务失败");
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，DN/SN/bankcode为空
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_06(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Empty");
        String[] split = str.split("%");
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, "", sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，DN/SN/bankcode为null
     *
     * @param sAlg 对称算法为DES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_07(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Null");
        String[] split = str.split("%");
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, null, sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 制作数字信封，DN/SN/bankcode为null
     *
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_08(String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Null or Empty");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, str, sAlg, str);
            if (upkiResult.getReturnCode() != -100203) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作数字信封（encryptEnvelope）:Base64证书信息传入为空字符串，可以制作信封成功");
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 对称算法为空或null
     *
     * @param sAlg
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_09(String sAlg) {
        System.out.println("Test ABCJEW EncryptEnvelope sAlg Null or Empty");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, null);
            if (upkiResult.getReturnCode() != -100203) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作数字信封（encryptEnvelope）:对称算法为空或null，可以制作信封成功");
            }
        } catch (Exception e) {
            Assert.fail("制作数字信封失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }
}
