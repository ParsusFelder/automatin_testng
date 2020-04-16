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
import java.util.Random;

/**
 * @author zhaoyongzhi
 * @ClassName: TestCUPNCPEncrypt
 * @date 2020-03-02 18:20
 * @Description: 银联无卡支付加密
 * <p>用例覆盖点：</p>
 * <p>1）</p>
 * <p>2）</p>
 * <p>3）</p>
 * <p>4）</p>
 * <p>5）</p>
 * <p>6）</p>
 * <p>7）</p>
 * <p>8）</p>
 * <p>9）</p>
 * <p>10）</p>
 * <p>11）</p>
 */
@Test(groups = "abcjew.cupncpencrypt")
public class TestCUPNCPEncrypt {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

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
     * 银联无卡支付加密，传证书DN
     *
     * @param dn   证书DN
     * @param sAlg 对称算法，覆盖3DES/DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "salg-0-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_01(String dn, String sAlg) {
        System.out.println("银联无卡支付加密：传证书DN");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100213) {
                    Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("银联无卡支付加密：银联无卡支付加密仅支持使用SM4对称算法，与文档不符，文档描述同时支持3DES");
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，传证书SN
     *
     * @param sn   证书SN
     * @param sAlg 对称算法，覆盖3DES/DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "salg-0-allsn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_02(String sn, String sAlg) {
        System.out.println("银联无卡支付加密：传证书SN");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, sn, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100213) {
                    Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("银联无卡支付加密：银联无卡支付加密仅支持使用SM4对称算法，与文档不符，文档描述同时支持3DES");
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，对称算法为null
     *
     * @param dn 证书DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_03(String dn) {
        System.out.println("银联无卡支付加密：对称算法为null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -1) {
                    Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("银联无卡支付加密：当对称算法为null时，未按照文档描述能够加密成功");
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，对称算法为空字符
     *
     * @param dn 证书DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_04(String dn) {
        System.out.println("银联无卡支付加密：对称算法为空字符");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "");
            if (upkiResult.getReturnCode() != -100213) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，证书DN为空或null
     *
     * @param dn 证书DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_05(String dn) {
        System.out.println("银联无卡支付加密：证书DN为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，原文为null
     */
    @Test(groups = "abcjew.cupncpencrypt.normal")
    public void testCUPNCPEncrypt_06() {
        System.out.println("银联无卡支付加密：原文为null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(null, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付加密，原文过大
     */
    @Test(groups = "abcjew.cupncpencrypt.normal")
    public void testCUPNCPEncrypt_07() {
        System.out.println("银联无卡支付加密：原文过大");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }
    }
}
