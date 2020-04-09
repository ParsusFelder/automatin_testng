package qa.infosec.testng.netsign.dataprovider.util;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Properties;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpATTRS;

/**
 * ʹ��SFTPЭ����ļ�����
 * <p>Title: SFTPFile</p>  
 * <p>Description: </p>  
 * @author maxf  
 * @date 2019��8��14��
 */
public class SFTPFile {
	
	/**
	 * ʹ��SFTPЭ������ָ���ļ���ָ��Ŀ¼
	 * @param sftp_user
	 * @param host
	 * @param port
	 * @param password
	 * @param filename
	 * @param dst
	 */
	public void downFile(String sftp_user, String host, String port, String password, String filename, String dst) {

		Session session = null;
		Channel channel = null;
		ChannelSftp c = null;
		// Map<String, String> sftpDetails = new HashMap<String, String>();
		// ��������ip���˿ڣ��û���������
		
		try {
			JSch jsch = new JSch();
			int iport = Integer.parseInt(port);
			session = jsch.getSession(sftp_user, host, iport);

			session.setPassword(password);

			Properties config = new Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);// ΪSession��������properties
			session.setTimeout(300);// ����timeoutʱ��
			session.connect();// ���ɹ���Session��������

			channel = session.openChannel("sftp");// ��SFTPͨ��
			channel.connect();
			c = (ChannelSftp) channel;

			@SuppressWarnings("unused")
			SftpATTRS attr = c.stat(filename);
			//long fileSize = attr.getSize();
			OutputStream out = new FileOutputStream(dst);
			c.get(filename, dst); // �����1
			out.close();
		} catch (JSchException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			c.disconnect();
			c.quit();
		}
	}

}
