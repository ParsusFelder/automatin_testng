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
 * @ClassName: TestCUPNCPDecrypt
 * @date 2020-04-16 11:20
 * @Description: 银联无卡支付解密
 * <p>用例覆盖点：</p>
 * <p>1）银联无卡支付解密：正确传入密文信息</p>
 * <p>2）银联无卡支付解密：对称密钥密文篡改</p>
 * <p>3）银联无卡支付解密：原文密文篡改</p>
 * <p>4）银联无卡支付解密：原文为null</p>
 * <p>5）银联无卡支付解密：证书DN传入为空或null</p>
 * <p>6）银联无卡支付解密：对称算法传入为空或null</p>
 */
@Test(groups = "abcjew.cpuncpdecrypt")
public class TestCUPNCPDecrypt {
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
     * 银联无卡支付解密：正确传入密文信息
     *
     * @param dn 证书主题
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_01(String dn) {
        System.out.println("银联无卡支付解密：正确传入密文信息");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != 0 || !upkiResult.getBoolResult()) {
                Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付解密：对称密钥密文篡改
     *
     * @param dn 证书主题
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_02(String dn) {
        System.out.println("银联无卡支付解密：对称密钥密文篡改");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }

        try {
            enc_text[0] = Utils.modifyData(enc_text[0], 5, 10, "abcde");
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != -100109 || upkiResult.getBoolResult()) {
                Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付解密：原文密文篡改
     *
     * @param dn 证书主题
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_03(String dn) {
        System.out.println("银联无卡支付解密：原文密文篡改");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }

        try {
            enc_text[1] = Utils.modifyData(enc_text[1], 5, 10, "abcde");
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if ((upkiResult.getReturnCode() != 0) || !upkiResult.getBoolResult()) {
                Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付解密：原文为null
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal")
    public void testCUPNCPDecrypt_04() {
        System.out.println("银联无卡支付解密：原文为null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(null, dn, "SM4");
            if ((upkiResult.getReturnCode() != -1026) || upkiResult.getBoolResult()) {
                Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付解密：证书DN传入为空或null
     *
     * @param dn 证书主题
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_05(String dn) {
        System.out.println("银联无卡支付解密：解密证书DN传入为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String enc_dn = "CN=c020crlfbdIssueModeHTTP";
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, enc_dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026 || upkiResult.getBoolResult()) {
                Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }

    /**
     * 银联无卡支付解密：对称算法传入为空或null
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_06(String sAlg) {
        System.out.println("银联无卡支付解密：解密证书DN传入为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String enc_dn = "CN=c020crlfbdIssueModeHTTP";
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, enc_dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("银联无卡支付加密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付加密失败" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, enc_dn, sAlg);
//            System.out.println(new String ((byte[]) upkiResult.getResults().get("plain_text")));
            if (upkiResult.getReturnCode() != -100110) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("银联无卡支付解密失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("银联无卡支付解密（CUPNCPDecrypt）：对称算法传入为null时能解密成功，但解密得到的数据错误");
            }
        } catch (Exception e) {
            Assert.fail("银联无卡支付解密失败" + e.getMessage());
        }
    }
}
