package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.PBCAgent2G;
import cn.com.infosec.netsign.agent.UpkiAgent;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestMakeCUPFacePayWLEnvelope
 * @date 2020-03-02 18:21
 * @Description:
 * <p>�������ǵ㣺</p>
 * <p>1������ˢ��֧�������ŷ�,�Գ���Կ����ΪSM4/AES</p>
 * <p>2������ˢ��֧�������ŷ�,�Գ���Կ����Ϊ3DES/DES</p>
 * <p>3��pinCryptoΪnull,�㷨����ΪSM4/AES</p>
 * <p>4��pinCryptoΪnull,�㷨����Ϊ3DES/DES</p>
 * <p>5��pinCrypto���Ĵ۸�,�Գ���Կ����SM4/AES</p>
 * <p>6��pinCrypto���Ĵ۸ģ��Գ���Կ����3DES/DES</p>
 * <p>7��ivΪnull,���ģʽΪ/ECB</p>
 * <p>8��ivΪnull,���ģʽΪ/CBC/CFB/OFB</p>
 * <p>9��iv ���ȴ���</p>
 * <p>10��iv �۸�</p>
 * <p>11��iv ����pin��������IV�����������������IV��һ��</p>
 * <p>12��pinModeAndPadding �����ʱʹ�õ����ģʽ��ƥ��</p>
 * <p>13��pinModeAndPadding ����Ϊ��</p>
 * <p>14��pinModeAndPadding ����Ϊnull</p>
 * <p>15��pinModeAndPadding �������ֵ</p>
 * <p>16��pinModeAndPadding ���ݴ���</p>
 * <p>17��noPaddingSecret ���貹λ���������ݣ����ȷ��㷨���鳤�����������㷨����ΪDES/3DES</p>
 * <p>18��noPaddingSecret ���貹λ���������ݣ����ȷ��㷨���鳤�����������㷨����ΪAES/SM4</p>
 * <p>19��noPaddingSecret ����Ϊnull</p>
 * <p>20��paddingSecret ���ȷ��㷨���鳤�����������㷨����Ϊ3DES/DES</p>
 * <p>21��paddingSecret ���ȷ��㷨���鳤�����������㷨����ΪAES/SM4</p>
 * <p>22��paddingSecret ����Ϊnull</p>
 * <p>23��paddingSecret ���ȷ��㷨���鳤��������,���ģʽΪ/CBC/NoPadding</p>
 * <p>24��modeAndPadding �������ģʽΪ��</p>
 * <p>25��modeAndPadding �������ģʽΪnull</p>
 * <p>26��encDN ��ȷDN���Գ��㷨����ΪDES/3DES</p>
 * <p>27��encDN ��ȷDN���Գ��㷨����ΪAES/SM4</p>
 * <p>28��encDN DN������</p>
 * <p>29��encDN DNΪ��</p>
 * <p>30��encDN DNΪnull</p>
 */
public class TestMakeCUPFacePayWLEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    PBCAgent2G pbc2g;
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
        pbc2g = init.start(ip,port,password,true,20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpsymmpath,
                ParameterUtil.localsymmpath);
        System.out.println("NetSignServerInit OK");
    }

}
