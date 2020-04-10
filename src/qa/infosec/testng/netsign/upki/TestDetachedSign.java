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
 * <p>�������ǵ㣺</p>
 * <p>1��plainTextԭ����ȷ��֤��DN��ժҪ�㷨��ȷ</p>
 * <p>2��plainTextԭ��Ϊnull</p>
 * <p>3��plainTextԭ��Ϊ��</p>
 * <p>4����Կ��֤��SN</p>
 * <p>5����Կ������</p>
 * <p>6��dnΪ�ջ�null</p>
 * <p>7��ժҪ�㷨Ϊ��</p>
 * <p>8��ժҪ�㷨Ϊnull</p>
 * <p>9��ժҪ�㷨����</p>
 * <p>10��ժҪ�㷨Сд</p>
 * <p>11����ԭ����ǩ��,SM2֤��</p>
 * <p>12����ԭ����ǩ��,RSA֤��</p>
 */
public class TestDetachedSign {
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
     * Detachedǩ����ԭ��������֤��dn��ժҪ�㷨��ȷ
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_01(String alg, String dn) {
        System.out.println("Detachedǩ��(detachedSign),���ξ���ȷ");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ���������������Σ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ���������������Σ����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����ԭ��Ϊnull
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_02(String alg, String dn) {
        System.out.println("Detachedǩ��(detachedSign),ԭ��Ϊnull");
        try {
            UpkiResult sign;
            sign = agent.detachedSign(null, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -100208) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������ԭ��Ϊnull��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������ԭ��Ϊnull�����쳣��" + e.getMessage());
        }
    }

    /**
     *Detachedǩ����ԭ��Ϊ���ַ���
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_03(String alg, String dn) {
        System.out.println("Detachedǩ��(detachedSign),ԭ��Ϊ���ַ���");
        try {
            UpkiResult sign;
            sign = agent.detachedSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -100100) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������ԭ��Ϊ���ַ�����ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������ԭ��Ϊ���ַ��������쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ������Կ��֤��SN
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "normal-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_04(String alg, String sn) {
        System.out.println("Detachedǩ��(detachedSign),��Կ��֤��SN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ����������Կ֤�鴫SN��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ����������Կ֤�鴫SN�����쳣��" + e.getMessage());
        }
    }


    /**
     * Detachedǩ�����������ڵ���Կ
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_05() {
        System.out.println("Detachedǩ��(detachedSign),�������ڵ���Կ");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, "bucunzaidemiyue", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100204) {
                Assert.fail(" ��E��ABCJEW-detachedǩ�������Բ����ڵ���Կ��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ�������Բ����ڵ���Կ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����DNΪ�ջ�null
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_06(String dn) {
        System.out.println("Detachedǩ��(detachedSign),DNΪ�ջ�null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������DNΪ�ջ�null��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������DNΪ�ջ�null�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����AlgΪ��
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_07(String dn) {
        System.out.println("Detachedǩ��(detachedSign),ժҪ�㷨AlgΪ��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, "");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����AlgΪnull
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_08(String dn) {
        System.out.println("Detachedǩ��(detachedSign),ժҪ�㷨AlgΪnull");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����Alg������
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_09() {
        System.out.println("Detachedǩ��(detachedSign),ժҪ�㷨Alg������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.detachedSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=10year_2048", "sss");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100112) {
                if (sign.getReturnCode() != -100103) {
                    Assert.fail(" ��E��ABCJEW-detachedǩ�������Բ����ڵ�ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
                }
                Reporter.log("��E��ABCJEW-detachedǩ�������Բ����ڵ�ժҪ�㷨�������벻����������Ϊ��"+sign.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ�������Բ����ڵ�ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ����AlgСд
     */
    @Test(groups = "abcjew.detachedsign.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedSign_10(String alg, String dn) {
        System.out.println("Detachedǩ��(detachedSign),ժҪ�㷨AlgСд");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            String littlealg = alg.toLowerCase();
            sign = agent.detachedSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ��������СдժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ��������СдժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ������ԭ�ģ�sm2֤��
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_11() {
        System.out.println("Detachedǩ��(detachedSign),��ԭ��");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
            String alg = "SM3";
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ�������Դ�ԭ�ģ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ�������Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }

    /**
     * Detachedǩ������ԭ�ģ�rsa֤��
     */
    @Test(groups = "abcjew.detachedsign.normal")
    public void testdetachedSign_12() {
        System.out.println("Detachedǩ��(detachedSign),��ԭ��");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
            String alg = "SHA1";
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detachedǩ�������Դ�ԭ�ģ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detachedǩ�������Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }
}