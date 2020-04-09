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
 * @author suiyixin
 * @ClassName: TestRawSign
 * @date 2020-3-3 10:50
 * <p>�������ǵ㣺</p>
 * <p>1��plainTextԭ����ȷ��֤��DN��ժҪ�㷨��ȷ</p>
 * <p>2��plainTextԭ��Ϊnull</p>
 * <p>3��plainTextԭ��Ϊ��</p>
 * <p>4����Կ��֤��SN</p>
 * <p>5����Կ��֤���������</p>
 * <p>6����Կ������</p>
 * <p>7��dnΪ�ջ�null</p>
 * <p>8��ժҪ�㷨Ϊ��</p>
 * <p>9��ժҪ�㷨Ϊnull</p>
 * <p>10��ժҪ�㷨����</p>
 * <p>11��ժҪ�㷨Сд</p>
 * <p>12����ԭ����ǩ��</p>
 */
public class TestRawSign {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

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
     * ��ǩ��ԭ��������֤��dn��ժҪ�㷨��ȷ
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_01(String alg, String dn) {
        System.out.println("��ǩ(rawSign),����������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ�������������Σ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ�������������Σ����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��ԭ��Ϊnull
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_02(String alg, String dn) {
        System.out.println("��ǩ(rawSign),ԭ��Ϊnull");
        try {
            UpkiResult sign;
            sign = agent.rawSign(null, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -1027) {
                Assert.fail(" ��E��ABCJEW��ǩ������ԭ��Ϊnull��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������ԭ��Ϊnull�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��ԭ��Ϊ��
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_03(String alg, String dn) {
        System.out.println("��ǩ(rawSign),ԭ��Ϊ��");
        try {
            UpkiResult sign;
            sign = agent.rawSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text != null || sign.getReturnCode() != -1027) {
                if (sign.getReturnCode() != 0) {
                    Assert.fail(" ��E��ABCJEW��ǩ������ԭ��Ϊ���ַ�����ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
                }
                Reporter.log("��E��ABCJEW��ǩ,ԭ�Ĵ����ַ���ǩ���ɹ�");
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������ԭ��Ϊ���ַ��������쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ����Կ��֤��SN
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "normal-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_04(String alg, String sn) {
        System.out.println("��ǩ(rawSign),��Կ��֤��SN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ��������Կ֤�鴫SN��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ��������Կ֤�鴫SN�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ����Կ��֤���������
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_05(String alg, String bankcode) {
        System.out.println("��ǩ(rawSign),��Կ��֤���������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, bankcode, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ��������Կ��֤��������룬ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ��������Կ��֤��������룬���쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ���������ڵ���Կ
     */
    @Test(groups = "abcjew.rawsign.normal")
    public void testrawSign_06() {
        System.out.println("��ǩ(rawSign),�������ڵ���Կ");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, "bucunzaidemiyue", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100204) {
                Assert.fail(" ��E��ABCJEW��ǩ�����Բ����ڵ���Կ��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ�����Բ����ڵ���Կ�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��DNΪ�ջ�null
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_07(String dn) {
        System.out.println("��ǩ(rawSign),DNΪ�ջ�null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, dn, "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ������DNΪ�ջ�null��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������DNΪ�ջ�null�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��AlgΪ��
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_08(String dn) {
        System.out.println("��ǩ(rawSign),ժҪ�㷨AlgΪ��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, dn, "");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������ժҪ�㷨Ϊ��ʹ��Ĭ��ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��AlgΪnull
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "keystore-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_09(String dn) {
        System.out.println("��ǩ(rawSign),ժҪ�㷨AlgΪnull");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ������ժҪ�㷨Ϊnullʹ��Ĭ��ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������ժҪ�㷨Ϊnullʹ��Ĭ��ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ��Alg������
     */
    @Test(groups = "abcjew.rawsign.normal")
    public void testrawSign_10() {
        System.out.println("��ǩ(rawSign),ժҪ�㷨Alg������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=10year_2048", "sss");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign.getReturnCode() != -100112) {
                Assert.fail(" ��E��ABCJEW��ǩ�����Բ����ڵ�ժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ�����Բ����ڵ�ժҪ�㷨�����쳣��" + e.getMessage());
        }

    }

    /**
     * ��ǩ��AlgСд
     */
    @Test(groups = "abcjew.rawsign.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawSign_11(String alg, String dn) {
        System.out.println("��ǩ(rawSign),ժҪ�㷨AlgСд");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            String littlealg = alg.toLowerCase();
            sign = agent.rawSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ������СдժҪ�㷨��ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ������СдժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ����ԭ�ģ�RSA֤��
     */
    @Test(groups = "abcjew.rawsign.normal")
    public void testrawSign_12() {
        System.out.println("��ǩ(rawSign),��ԭ��,RSA֤��");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String alg = "SHA1";
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ�����Դ�ԭ�ģ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ�����Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }

    /**
     * ��ǩ����ԭ�ģ�SM2֤��
     */
    @Test(groups = "abcjew.rawsign.normal")
    public void testrawSign_13() {
        System.out.println("��ǩ(rawSign),��ԭ��,SM2֤��");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            String alg = "SM3";
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            if (sign_text == null || sign.getReturnCode() != 0 || !"success".equals(sign.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW��ǩ�����Դ�ԭ�ģ�ʧ�ܣ�" + sign.getReturnCode() + sign.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW��ǩ�����Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }
}
