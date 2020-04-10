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
 * @Description: �ǶԳƼ���
 * <p>�������ǵ㣺</p>
 * <p>1���ǶԳƼ���,֤����DNƥ��</p>
 * <p>2���ǶԳƼ���,DNΪnull</p>
 * <p>3���ǶԳƼ���,֤��Ϊnull</p>
 * <p>4���ǶԳƼ��ܣ�ʹ��SN����</p>
 * <p>5���ǶԳƼ��ܣ�ʹ��BankCode����</p>
 * <p>6���ǶԳƼ��ܣ�ʹ�ô��ں�������BankCode����</p>
 * <p>7���ǶԳƼ��ܣ�ʹ�ô����DN/SN/BankCode����</p>
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
     * �ǶԳƼ���,֤����DNƥ��
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
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƼ���,DNΪnull
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
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƼ���,֤��Ϊnull
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
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƼ��ܣ�ʹ��SN����
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
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƼ��ܣ�ʹ��BankCode����
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
                    Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * �ǶԳƼ��ܣ�ʹ�ô��ں�������BankCode����
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
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƼ��ܣ�ʹ�ô����DN/SN/BankCode����
     */
    @Test(groups = "abcjew.unsymmencrypt.normal")
    public void testUnsymmEncrypt_07() {
        System.out.println("Test UnsymmEncrypt DN Base64 Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        try {
            upkiResult = agent.unsymmEncrypt("CN=123", pOrgData, null);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }
}
