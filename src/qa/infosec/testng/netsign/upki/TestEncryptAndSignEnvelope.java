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
 * @ClassName: TestEncryptAndSignEnvelope
 * @date 2020-03-02 18:07
 * @Description: 制作带签名的数字信封
 * <p>用例覆盖点：</p>
 * <p>1）制作带签名的数字信封，使用RSA证书DN</p>
 * <p>2）制作带签名的数字信封，使用SM2证书DN</p>
 * <p>3）制作带签名的数字信封，使用RSA证书SN</p>
 * <p>4）制作带签名的数字信封，使用SM2证书SN</p>
 * <p>5）制作带签名的数字信封，使用RSA证书BankCode</p>
 * <p>6）制作带签名的数字信封，使用SM2证书BankCode</p>
 * <p>7）制作带签名的数字信封，原文为null</p>
 * <p>8）制作带签名的数字信封，DN/SN/Bankcode为空或null</p>
 * <p>9）制作带签名的数字信封，摘要/对称算法为空或null</p>
 * <p>10）制作带签名的数字信封，DN不存在</p>
 * <p>11）制作带签名的数字信封，摘要算法错误</p>
 * <p>12）制作带签名的数字信封，对称算法错误</p>
 * <p>13）制作带签名的数字信封，摘要/对称算法小写输入</p>
 */
@Test(groups = "abcjew.encryptandsignenvelope")
public class TestEncryptAndSignEnvelope {
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
     * 制作带签名的数字信封，使用RSA证书DN
     *
     * @param DN   RSA证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_01(String DN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用RSA证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，使用SM2证书DN
     *
     * @param DN   SM2证书DN
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_02(String DN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用SM2证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，使用RSA证书SN
     *
     * @param SN   RSA证书SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-sn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_03(String SN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用RSA证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，使用SM2证书SN
     *
     * @param SN   SM2证书SN
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-sn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_04(String SN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用SM2证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，使用RSA证书Bankcode
     *
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-bankcode-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_05(String bankcode, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用RSA证书BankCode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, bankcode, bankcode, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203 && upkiResult.getReturnCode() != -100204) {
                    Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作带签名的数字信封（encryptAndSignEnvelope）：部分证书无法通过Bankcode识别，导致执行方法时服务报错，无法找到证书主题");
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，使用SM2证书Bankcode
     *
     * @param dAlg SHA1/SHA256/SM3
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-bankcode-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_06(String bankcode, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），使用SM2证书BankCode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, bankcode, bankcode, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203 && upkiResult.getReturnCode() != -100204) {
                    Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("制作带签名的数字信封（encryptAndSignEnvelope）：部分证书无法通过Bankcode识别，导致执行方法时服务报错，无法找到证书主题");
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，原文为null
     *
     * @param DN   SM2证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "sm2-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_07(String DN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），原文为null");

        byte[] pOrgData = null;
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != -100208) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，DN/SN/Bankcode为空或null
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_08(String DN) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），DN/SN/Bankcode为空或null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("制作带签名的数字信封（encryptAndSignEnvelope）:DN/SN/Bankcode为空或null，可做业务成功");
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，摘要/对称算法为空或null
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_09(String alg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），摘要/对称算法为空或null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, alg, alg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("制作带签名的数字信封（encryptAndSignEnvelope）:摘要/对称算法为空或null，可做业务成功");
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，DN不存在
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_10() {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），DN不存在");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA1";
        String salg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，摘要算法错误
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_11() {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），摘要算法错误");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA";
        String salg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，对称算法错误
     *
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal")
    public void testEncryptAndSignEnvelope_12() {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），对称算法错误");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String DN = "CN=c020crlfbdIssueModeHP";
        String dalg = "SHA1";
        String salg = "AES1";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dalg, salg);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，摘要算法小写输入
     *
     * @param DN   RSA证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_13(String DN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），摘要算法小写输入");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg.toLowerCase(), sAlg);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 制作带签名的数字信封，对称算法小写输入
     *
     * @param DN   RSA证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.encryptandsignenvelope.normal", dataProvider = "rsa-dn-dalg-0", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptAndSignEnvelope_14(String DN, String dAlg, String sAlg) {
        System.out.println("制作带签名的数字信封（encryptAndSignEnvelope），对称算法小写输入");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg.toLowerCase());
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("制作带签名的数字信封（encryptAndSignEnvelope）：对称算法不支持小写输入");
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
    }
}
