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
 * @author suiyixin
 * @ClassName: TestDetachedSign
 * @date 2020-03-10 09:50
 * @Description:
 * <p>用例覆盖点：</p>
 * <p>1）plainText原文正确，证书DN和摘要算法正确</p>
 * <p>2）plainText原文为null</p>
 * <p>3）plainText原文为空</p>
 * <p>4）密钥传证书SN</p>
 * <p>5）密钥不存在</p>
 * <p>6）dn为空或null</p>
 * <p>7）摘要算法为空</p>
 * <p>8）摘要算法为null</p>
 * <p>9）摘要算法有误</p>
 * <p>10）摘要算法小写</p>
 * <p>11）大原文做签名,SM2证书</p>
 * <p>12）大原文做签名,RSA证书</p>
 */
public class TestDetachedSign {
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
     * Detached签名，原文正常，证书dn和摘要算法正确
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_01(String alg, String dn) {
        System.out.println("Detached签名(detachedSign),传参均正确");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试正常传参，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试正常传参，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，原文为null
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_02(String alg, String dn) {
        System.out.println("Detached签名(detachedSign),原文为null");
        try {
            UpkiResult sign;
            sign = agent.detachedSign(null, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -100208) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试原文为null，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试原文为null，抛异常！" + e.getMessage());
        }
    }

    /**
     *Detached签名，原文为空字符串
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_03(String alg, String dn) {
        System.out.println("Detached签名(detachedSign),原文为空字符串");
        try {
            UpkiResult sign;
            sign = agent.detachedSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -100100) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试原文为空字符串，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试原文为空字符串，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，密钥传证书SN
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "normal-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_04(String alg, String sn) {
        System.out.println("Detached签名(detachedSign),密钥传证书SN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试密钥证书传SN，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试密钥证书传SN，抛异常！" + e.getMessage());
        }
    }


    /**
     * Detached签名，传不存在的密钥
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_05() {
        System.out.println("Detached签名(detachedSign),传不存在的密钥");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, "bucunzaidemiyue", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100204) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试不存在的密钥，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试不存在的密钥，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，DN为空或null
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_06(String dn) {
        System.out.println("Detached签名(detachedSign),DN为空或null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试DN为空或null，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试DN为空或null，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，Alg为空
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_07(String dn) {
        System.out.println("Detached签名(detachedSign),摘要算法Alg为空");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, "");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试摘要算法为空使用默认摘要算法，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试摘要算法为空使用默认摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，Alg为null
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_08(String dn) {
        System.out.println("Detached签名(detachedSign),摘要算法Alg为null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试摘要算法为空使用默认摘要算法，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试摘要算法为空使用默认摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，Alg不存在
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_09() {
        System.out.println("Detached签名(detachedSign),摘要算法Alg不存在");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=10year_2048", "sss");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100112) {
                if (sign.getReturnCode() != -100103) {
                    Assert.fail(" 金E卫ABCJEW-detached签名，测试不存在的摘要算法，失败！" + sign.getReturnCode() + sign.getReturnContent());
                }
                Reporter.log("金E卫ABCJEW-detached签名，测试不存在的摘要算法，错误码不合理，错误码为："+sign.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试不存在的摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，Alg小写
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_10(String alg, String dn) {
        System.out.println("Detached签名(detachedSign),摘要算法Alg小写");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            String littlealg = alg.toLowerCase();
            sign = agent.detachedSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试小写摘要算法，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试小写摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，大原文，sm2证书
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_11() {
        System.out.println("Detached签名(detachedSign),大原文");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
            String alg = "SM3";
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试大原文，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试大原文，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached签名，大原文，rsa证书
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_12() {
        System.out.println("Detached签名(detachedSign),大原文");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
            String alg = "SHA1";
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached签名，测试大原文，失败！" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached签名，测试大原文，抛异常！" + e.getMessage());
        }
    }
}