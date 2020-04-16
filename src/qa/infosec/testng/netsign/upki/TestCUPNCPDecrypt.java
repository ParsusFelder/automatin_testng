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
 * @Description: �����޿�֧������
 * <p>�������ǵ㣺</p>
 * <p>1�������޿�֧�����ܣ���ȷ����������Ϣ</p>
 * <p>2�������޿�֧�����ܣ��Գ���Կ���Ĵ۸�</p>
 * <p>3�������޿�֧�����ܣ�ԭ�����Ĵ۸�</p>
 * <p>4�������޿�֧�����ܣ�ԭ��Ϊnull</p>
 * <p>5�������޿�֧�����ܣ�֤��DN����Ϊ�ջ�null</p>
 * <p>6�������޿�֧�����ܣ��Գ��㷨����Ϊ�ջ�null</p>
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
        // ����netsignconfig.properties�����ļ�����ȡ������Ϣ,confpath=null ʹ��Ĭ��·��
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
     * �����޿�֧�����ܣ���ȷ����������Ϣ
     *
     * @param dn ֤������
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_01(String dn) {
        System.out.println("�����޿�֧�����ܣ���ȷ����������Ϣ");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != 0 || !upkiResult.getBoolResult()) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ��Գ���Կ���Ĵ۸�
     *
     * @param dn ֤������
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_02(String dn) {
        System.out.println("�����޿�֧�����ܣ��Գ���Կ���Ĵ۸�");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }

        try {
            enc_text[0] = Utils.modifyData(enc_text[0], 5, 10, "abcde");
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != -100109 || upkiResult.getBoolResult()) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�ԭ�����Ĵ۸�
     *
     * @param dn ֤������
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_03(String dn) {
        System.out.println("�����޿�֧�����ܣ�ԭ�����Ĵ۸�");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }

        try {
            enc_text[1] = Utils.modifyData(enc_text[1], 5, 10, "abcde");
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if ((upkiResult.getReturnCode() != 0) || !upkiResult.getBoolResult()) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�ԭ��Ϊnull
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal")
    public void testCUPNCPDecrypt_04() {
        System.out.println("�����޿�֧�����ܣ�ԭ��Ϊnull");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] enc_text = null;
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(null, dn, "SM4");
            if ((upkiResult.getReturnCode() != -1026) || upkiResult.getBoolResult()) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�֤��DN����Ϊ�ջ�null
     *
     * @param dn ֤������
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_05(String dn) {
        System.out.println("�����޿�֧�����ܣ�����֤��DN����Ϊ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String enc_dn = "CN=c020crlfbdIssueModeHTTP";
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, enc_dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026 || upkiResult.getBoolResult()) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ��Գ��㷨����Ϊ�ջ�null
     */
    @Test(groups = "abcjew.cpuncpdecrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPDecrypt_06(String sAlg) {
        System.out.println("�����޿�֧�����ܣ�����֤��DN����Ϊ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String enc_dn = "CN=c020crlfbdIssueModeHTTP";
        String[] enc_text = null;
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, enc_dn, "SM4");
            enc_text = (String[]) upkiResult.getResults().get("enc_text");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }

        try {
            UpkiResult upkiResult = agent.CUPNCPDecrypt(enc_text, enc_dn, sAlg);
//            System.out.println(new String ((byte[]) upkiResult.getResults().get("plain_text")));
            if (upkiResult.getReturnCode() != -100110) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("�����޿�֧�����ܣ�CUPNCPDecrypt�����Գ��㷨����Ϊnullʱ�ܽ��ܳɹ��������ܵõ������ݴ���");
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }
}
