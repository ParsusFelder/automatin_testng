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
 * @ClassName: TestDecryptWangLianEnvelope
 * @date 2020-03-02 18:06
 * @Description: 解密网联格式数字信封
 * <p>用例覆盖点：</p>
 * <p>1）解密网联格式数字信封（decryptWangLianEnvelope）,对称算法为SM4/AES</p>
 * <p>2）解密网联格式数字信封（decryptWangLianEnvelope）,使用证书SN</p>
 * <p>3）解密网联格式数字信封（decryptWangLianEnvelope）,使用证书BankCode</p>
 * <p>4）解密网联格式数字信封（decryptWangLianEnvelope）,使用无私钥证书的BankCode</p>
 * <p>5）解密网联格式数字信封（decryptWangLianEnvelope）,密文为空</p>
 * <p>6）解密网联格式数字信封（decryptWangLianEnvelope）,密文篡改</p>
 * <p>7）解密网联格式数字信封（decryptWangLianEnvelope）,DN为空</p>
 * <p>8）解密网联格式数字信封（decryptWangLianEnvelope）,DN为null</p>
 * <p>9）解密网联格式数字信封（decryptWangLianEnvelope）,解密DN不匹配</p>
 */
@Test(groups = "abcjew.decryptwanglianenvelope")
public class TestDecryptWangLianEnvelope {
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
     * 解密网联格式数字信封,对称算法为SM4/AES
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_01(String sCertDN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,对称算法为SM4/AES");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertDN);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,使用证书SN
     *
     * @param sCertSN 证书SN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-allsn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_02(String sCertSN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,使用证书SN");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;

        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertSN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertSN);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,使用证书BankCode
     *
     * @param sCertBankCode 证书BankCode
     * @param sAlg          对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-allbankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_03(String sCertBankCode, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,使用证书BankCode");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("10year".equals(sCertBankCode) || "RSARoot2048".equals(sCertBankCode)) {
            return;
        }
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,使用无私钥证书的BankCode
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal")
    public void testDecryptWangLianEnvelope_04() {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,使用无私钥证书的BankCode");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sCertBankCode = "RSARoot2048";
        String sAlg = "AES";
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            if (upkiResult1.getReturnCode() != -100203) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,使用无私钥证书的BankCode
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_05(String str) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,密文为空");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        String sCertBankCode = "CN=c020crlfbdIssueModeHTTP";

        // 解密网联格式数字信封
        try {
            String[] strs = new String[1];
            strs[0] = str;
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            if (upkiResult1.getReturnCode() != -1022) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,密文篡改
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_06(String sCertDN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,密文篡改");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            // 篡改加密密文
            strs[0] = Utils.modifyData(strs[0], 5, 10, "abcdef");
            strs[1] = Utils.modifyData(strs[1], 5, 10, "zhaoyongzhi");

            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertDN);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,DN为空
     *
     * @param sCertDN 证书DN
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_07(String sCertDN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,DN为空");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, "");
            if (upkiResult1.getReturnCode() != -100212) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("解密网联格式数字信封（decryptWangLianEnvelope）：解密网联格式数字信封，当DN传入空字符时，会使用加密证书列表配置的第一张证书");
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,DN为null
     *
     * @param sCertDN 证书null
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_08(String sCertDN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,DN为null");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, null);
            if (upkiResult1.getReturnCode() != -100212) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("解密网联格式数字信封（decryptWangLianEnvelope）：解密网联格式数字信封，当DN传入空字符时，会使用加密证书列表配置的第一张证书");
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解密网联格式数字信封,解密DN不匹配
     *
     * @param sCertDN 证书null
     * @param sAlg    对称算法
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_09(String sCertDN, String sAlg) {
        System.out.println("解密网联格式数字信封（decryptWangLianEnvelope）,解密DN不匹配");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // 制作网联格式数字信封
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("制作网联格式数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }
        // 解密网联格式数字信封
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, "CN=123");
            if (upkiResult1.getReturnCode() != -100203) {
                Assert.fail("解密网联格式数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解密网联格式数字信封失败：" + e.getMessage());
        }
    }
}
