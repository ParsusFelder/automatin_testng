package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
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
 * @ClassName: TestUnsymmEncrypt
 * @date 2020-03-02 18:01
 * @Description: 非对称加密
 * <p>用例覆盖点：</p>
 * <p>1）非对称加密,证书与DN匹配</p>
 * <p>2）非对称加密,DN为null</p>
 * <p>3）非对称加密,证书为null</p>
 * <p>4）非对称加密，使用SN加密</p>
 * <p>5）非对称加密，使用BankCode加密</p>
 * <p>6）非对称加密，使用处于黑名单的BankCode加密</p>
 * <p>7）非对称加密，使用错误的DN/SN/BankCode加密</p>
 */
@Test(groups = "abcjew.unsymmencrypt")
public class TestUnsymmEncrypt {
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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
    }

    /**
     * 非对称加密,证书与DN匹配
     */
    @Test(groups = "abcjew.unsymmencrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmEncrypt_01(String str) {
        System.out.println("Test UnsymmEncrypt DN Base64 Normal");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt(DN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 非对称加密,DN为null
     */
    @Test(groups = "abcjew.unsymmencrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmEncrypt_02(String str) {
        System.out.println("Test UnsymmEncrypt DN null");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt(null, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 非对称加密,证书为null
     */
    @Test(groups = "abcjew.unsymmencrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmEncrypt_03(String str) {
        System.out.println("Test UnsymmEncrypt Base64Cert Null");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt(DN, pOrgData, null);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 非对称加密，使用SN加密
     */
    @Test(groups = "abcjew.unsymmencrypt.normal", dataProvider = "allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmEncrypt_04(String str) {
        System.out.println("Test UnsymmEncrypt SN Base64 Normal");
        String[] split = str.split("%");
        String SN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt(SN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 非对称加密，使用BankCode加密
     */
    @Test(groups = "abcjew.unsymmencrypt.normal", dataProvider = "bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmEncrypt_05(String bankcode) {
        System.out.println("Test UnsymmEncrypt BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        if (!"10year".equals(bankcode)) {
            upkiResult = agent.unsymmEncrypt(bankcode, pOrgData, null);
            try {
                if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                    Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * 非对称加密，使用处于黑名单的BankCode加密
     */
    @Test(groups = "abcjew.unsymmencrypt.normal")
    public void testUnsymmEncrypt_06() {
        System.out.println("Test UnsymmEncrypt BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        String bankcode = "10year";
        upkiResult = agent.unsymmEncrypt(bankcode, pOrgData, null);
        try {
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 非对称加密，使用错误的DN/SN/BankCode加密
     */
    @Test(groups = "abcjew.unsymmencrypt.normal")
    public void testUnsymmEncrypt_07() {
        System.out.println("Test UnsymmEncrypt DN Base64 Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt("CN=123", pOrgData, null);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("非对称加密失败：" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("非对称加密失败：" + upkiResult.getReturnCode() + e.getMessage());
        }
    }
}
