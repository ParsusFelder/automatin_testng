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
 * @ClassName: TestCUPNCPRawSign
 * @date 2020-03-23 10:19
 * @Description: 编制银联无卡支付裸签名
 * <p>用例覆盖点：</p>
 * <p>1）编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书DN做签名</p>
 * <p>2）编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书SN做签名</p>
 * <p>3）编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书Bankcode做签名</p>
 * <p>4）编制银联无卡支付裸签名（CUPNCPRawSign）：原文为null</p>
 * <p>5）编制银联无卡支付裸签名（CUPNCPRawSign）：DN/SN/Bankcode为空或null</p>
 * <p>6）编制银联无卡支付裸签名（CUPNCPRawSign）：DN错误</p>
 * <p>7）编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法为空或null</p>
 * <p>8）编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法错误</p>
 * <p>9）编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,RSA证书</p>
 * <p>9）编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,SM2证书</p>
 */
@Test(groups = "abcjew.cupncprawsign")
public class TestCUPNCPRawSign {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // 解析netsignconfig.properties配置文件，获取所需信息,confpath=null 使用默认路径
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书DN做签名
     *
     * @param alg 摘要算法
     * @param dn  RSA/SM2证书DN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_01(String alg, String dn) {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书DN做签名");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书SN做签名
     *
     * @param alg 摘要算法
     * @param sn  RSA/SM2证书SN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_02(String alg, String sn) {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书SN做签名");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书Bankcode做签名
     *
     * @param alg      摘要算法
     * @param bankcode RSA/SM2证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_03(String alg, String bankcode) {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书Bankcode做签名");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：原文为null
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_04() {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：原文为null");

        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(null, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -1026) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：DN/SN/Bankcode为空或null
     *
     * @param dn RSA/SM2证书DN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_05(String dn) {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：使用RSA/SM2证书DN做签名");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("编制银联无卡支付裸签名（CUPNCPRawSign）:DN/SN/Bankcode为空或null,可签名成功");
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：DN错误
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_06() {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：DN错误");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "CN=123";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -100204) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法为空或null
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_07(String alg) {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -1026) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法错误
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_08() {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：摘要算法错误");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA3";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -100112) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,RSA证书
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_09() {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,RSA证书");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * 编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,SM2证书
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_10() {
        System.out.println("编制银联无卡支付裸签名（CUPNCPRawSign）：大原文做签名,SM2证书");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SM3";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }
}
