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
 * @Description: �����޿�֧������
 * <p>�������ǵ㣺</p>
 * <p>1��</p>
 * <p>2��</p>
 * <p>3��</p>
 * <p>4��</p>
 * <p>5��</p>
 * <p>6��</p>
 * <p>7��</p>
 * <p>8��</p>
 * <p>9��</p>
 * <p>10��</p>
 * <p>11��</p>
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
     * �����޿�֧�����ܣ���֤��DN
     *
     * @param dn   ֤��DN
     * @param sAlg �Գ��㷨������3DES/DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "salg-0-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_01(String dn, String sAlg) {
        System.out.println("�����޿�֧�����ܣ���֤��DN");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100213) {
                    Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("�����޿�֧�����ܣ������޿�֧�����ܽ�֧��ʹ��SM4�Գ��㷨�����ĵ��������ĵ�����ͬʱ֧��3DES");
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ���֤��SN
     *
     * @param sn   ֤��SN
     * @param sAlg �Գ��㷨������3DES/DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "salg-0-allsn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_02(String sn, String sAlg) {
        System.out.println("�����޿�֧�����ܣ���֤��SN");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, sn, sAlg);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100213) {
                    Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("�����޿�֧�����ܣ������޿�֧�����ܽ�֧��ʹ��SM4�Գ��㷨�����ĵ��������ĵ�����ͬʱ֧��3DES");
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ��Գ��㷨Ϊnull
     *
     * @param dn ֤��DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_03(String dn) {
        System.out.println("�����޿�֧�����ܣ��Գ��㷨Ϊnull");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -1) {
                    Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("�����޿�֧�����ܣ����Գ��㷨Ϊnullʱ��δ�����ĵ������ܹ����ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ��Գ��㷨Ϊ���ַ�
     *
     * @param dn ֤��DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "all-cert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_04(String dn) {
        System.out.println("�����޿�֧�����ܣ��Գ��㷨Ϊ���ַ�");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "");
            if (upkiResult.getReturnCode() != -100213) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�֤��DNΪ�ջ�null
     *
     * @param dn ֤��DN
     */
    @Test(groups = "abcjew.cupncpencrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPEncrypt_05(String dn) {
        System.out.println("�����޿�֧�����ܣ�֤��DNΪ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�ԭ��Ϊnull
     */
    @Test(groups = "abcjew.cupncpencrypt.normal")
    public void testCUPNCPEncrypt_06() {
        System.out.println("�����޿�֧�����ܣ�ԭ��Ϊnull");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(null, dn, "SM4");
            if (upkiResult.getReturnCode() != -1026) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }

    /**
     * �����޿�֧�����ܣ�ԭ�Ĺ���
     */
    @Test(groups = "abcjew.cupncpencrypt.normal")
    public void testCUPNCPEncrypt_07() {
        System.out.println("�����޿�֧�����ܣ�ԭ�Ĺ���");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            UpkiResult upkiResult = agent.CUPNCPEncrypt(plainText, dn, "SM4");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("�����޿�֧������ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("�����޿�֧������ʧ��" + e.getMessage());
        }
    }
}
