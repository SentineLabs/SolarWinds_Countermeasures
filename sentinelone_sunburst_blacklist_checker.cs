using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.Diagnostics;
using System.Management;
using System.IO;

namespace SentinelLabs
{
	class SunburstChecker
	{
		public static readonly ulong[] hashes_processes = new ulong[]
		{
			2597124982561782591UL,
			2600364143812063535UL,
			13464308873961738403UL,
			4821863173800309721UL,
			12969190449276002545UL,
			3320026265773918739UL,
			12094027092655598256UL,
			10657751674541025650UL,
			11913842725949116895UL,
			5449730069165757263UL,
			292198192373389586UL,
			12790084614253405985UL,
			5219431737322569038UL,
			15535773470978271326UL,
			7810436520414958497UL,
			13316211011159594063UL,
			13825071784440082496UL,
			14480775929210717493UL,
			14482658293117931546UL,
			8473756179280619170UL,
			3778500091710709090UL,
			8799118153397725683UL,
			12027963942392743532UL,
			576626207276463000UL,
			7412338704062093516UL,
			682250828679635420UL,
			13014156621614176974UL,
			18150909006539876521UL,
			10336842116636872171UL,
			12785322942775634499UL,
			13260224381505715848UL,
			17956969551821596225UL,
			8709004393777297355UL,
			14256853800858727521UL,
			8129411991672431889UL,
			15997665423159927228UL,
			10829648878147112121UL,
			9149947745824492274UL,
			3656637464651387014UL,
			3575761800716667678UL,
			4501656691368064027UL,
			10296494671777307979UL,
			14630721578341374856UL,
			4088976323439621041UL,
			9531326785919727076UL,
			6461429591783621719UL,
			6508141243778577344UL,
			10235971842993272939UL,
			2478231962306073784UL,
			9903758755917170407UL,
			14710585101020280896UL,
			14710585101020280896UL,
			13611814135072561278UL,
			2810460305047003196UL,
			2032008861530788751UL,
			27407921587843457UL,
			6491986958834001955UL,
			2128122064571842954UL,
			10484659978517092504UL,
			8478833628889826985UL,
			10463926208560207521UL,
			7080175711202577138UL,
			8697424601205169055UL,
			7775177810774851294UL,
			16130138450758310172UL,
			506634811745884560UL,
			18294908219222222902UL,
			3588624367609827560UL,
			9555688264681862794UL,
			5415426428750045503UL,
			3642525650883269872UL,
			13135068273077306806UL,
			3769837838875367802UL,
			191060519014405309UL,
			1682585410644922036UL,
			7878537243757499832UL,
			13799353263187722717UL,
			1367627386496056834UL,
			12574535824074203265UL,
			16990567851129491937UL,
			8994091295115840290UL,
			13876356431472225791UL,
			14968320160131875803UL,
			14868920869169964081UL,
			106672141413120087UL,
			79089792725215063UL,
			5614586596107908838UL,
			3869935012404164040UL,
			3538022140597504361UL,
			14111374107076822891UL,
			7982848972385914508UL,
			8760312338504300643UL,
			17351543633914244545UL,
			7516148236133302073UL,
			15114163911481793350UL,
			15457732070353984570UL,
			16292685861617888592UL,
			10374841591685794123UL,
			3045986759481489935UL,
			17109238199226571972UL,
			6827032273910657891UL,
			5945487981219695001UL,
			8052533790968282297UL,
			17574002783607647274UL,
			3341747963119755850UL,
			14193859431895170587UL,
			17439059603042731363UL,
			17683972236092287897UL,
			700598796416086955UL,
			3660705254426876796UL,
			12709986806548166638UL,
			3890794756780010537UL,
			2797129108883749491UL,
			3890769468012566366UL,
			14095938998438966337UL,
			11109294216876344399UL,
			1368907909245890092UL,
			11818825521849580123UL,
			8146185202538899243UL,
			2934149816356927366UL,
			13029357933491444455UL,
			6195833633417633900UL,
			2760663353550280147UL,
			16423314183614230717UL,
			2532538262737333146UL,
			4454255944391929578UL,
			6088115528707848728UL,
			13611051401579634621UL,
			18147627057830191163UL,
			17633734304611248415UL,
			13581776705111912829UL,
			7175363135479931834UL,
			3178468437029279937UL,
			13599785766252827703UL,
			6180361713414290679UL,
			8612208440357175863UL,
			8408095252303317471UL
		};

		public static readonly ulong[] hashes_drivers = new ulong[]
		{
			17097380490166623672UL,
			15194901817027173566UL,
			12718416789200275332UL,
			18392881921099771407UL,
			3626142665768487764UL,
			12343334044036541897UL,
			397780960855462669UL,
			6943102301517884811UL,
			13544031715334011032UL,
			11801746708619571308UL,
			18159703063075866524UL,
			835151375515278827UL,
			16570804352575357627UL,
			1614465773938842903UL,
			12679195163651834776UL,
			2717025511528702475UL,
			17984632978012874803UL
		};

		public static readonly ulong[] hashes_services = new ulong[]
		{
			5183687599225757871UL,
			917638920165491138UL,
			10063651499895178962UL,
			16335643316870329598UL,
			10501212300031893463UL,
			155978580751494388UL,
			17204844226884380288UL,
			5984963105389676759UL,
			11385275378891906608UL,
			13693525876560827283UL,
			17849680105131524334UL,
			18246404330670877335UL,
			8698326794961817906UL,
			9061219083560670602UL,
			11771945869106552231UL,
			9234894663364701749UL,
			8698326794961817906UL,
			15695338751700748390UL,
			640589622539783622UL,
			15695338751700748390UL,
			9384605490088500348UL,
			6274014997237900919UL,
			15092207615430402812UL,
			3320767229281015341UL,
			3200333496547938354UL,
			14513577387099045298UL,
			607197993339007484UL,
			15587050164583443069UL,
			9559632696372799208UL,
			4931721628717906635UL,
			3200333496547938354UL,
			2589926981877829912UL,
			17997967489723066537UL,
			14079676299181301772UL,
			17939405613729073960UL,
			521157249538507889UL,
			14971809093655817917UL,
			10545868833523019926UL,
			15039834196857999838UL,
			14055243717250701608UL,
			5587557070429522647UL,
			12445177985737237804UL,
			17978774977754553159UL,
			17017923349298346219UL,
			17624147599670377042UL,
			16066651430762394116UL,
			13655261125244647696UL,
			12445177985737237804UL,
			3421213182954201407UL,
			14243671177281069512UL,
			16112751343173365533UL,
			3425260965299690882UL,
			9333057603143916814UL,
			3413886037471417852UL,
			7315838824213522000UL,
			13783346438774742614UL,
			2380224015317016190UL,
			3413052607651207697UL,
			3407972863931386250UL,
			10393903804869831898UL,
			12445232961318634374UL,
			3421197789791424393UL,
			541172992193764396UL
		};

		private static ulong GetHash(string s)
		{
			ulong num = 14695981039346656037UL;
			try
			{
				foreach (byte b in Encoding.UTF8.GetBytes(s))
				{
					num ^= (ulong)b;
					num *= 1099511628211UL;
				}
			}
			catch
			{
			}
			return num ^ 6605813339339102567UL;
		}

		private static bool is_blacklisted_process(ulong process_hash)
        {
			if (Array.IndexOf<ulong>(hashes_processes, process_hash) != -1)
			{
				return true; 
			}
			return false;
		}

		private static bool will_disable_service(ulong service_hash)
        {
			if (Array.IndexOf<ulong>(hashes_services, service_hash) != -1)
			{
				return true;
			}
			return false;
		}

		private static List<KeyValuePair<ulong, string>> get_blacklisted_drivers()
        {
			List<KeyValuePair<ulong, string>> blacklisted_drivers_found = new List<KeyValuePair<ulong, string>>();
			using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_SystemDriver"))
			{
				foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
				{
					string driver_name = Path.GetFileName(((ManagementObject)managementBaseObject).Properties["PathName"].Value.ToString());
					ulong driver_hash = GetHash(driver_name.ToLower());
					if (Array.IndexOf<ulong>(hashes_drivers, driver_hash) != -1)
					{
						blacklisted_drivers_found.Add(new KeyValuePair<ulong, string>(driver_hash, driver_name));
					}
				}
			}
			return blacklisted_drivers_found;
		}

		private static void run_processes_check()
        {
			Console.WriteLine("[+] Checking running processes/services...");
			Process[] processes = Process.GetProcesses();
			for (int i = 0; i < processes.Length; i++)
			{
				string process_name = processes[i].ProcessName;
				ulong hash = GetHash(process_name.ToLower());
				if (is_blacklisted_process(hash))
				{
					Console.WriteLine(String.Format("BLACKLIST MATCH: Running process {1} matches hardcoded blacklist hash {0}", hash, process_name));
					Console.WriteLine("OUTCOME: SUNBURST will exit!\n");
				}
				if (will_disable_service(hash))
				{
					Console.WriteLine(String.Format("SERVICES BLACKLIST MATCH: Running process {1} matches hardcoded blacklist hash {0}", hash, process_name));
					Console.WriteLine("OUTCOME: SUNBURST will attempt to disable via the services registry key!\n");
				}
			}
			Console.WriteLine("[+] Done checking running processes/services!");
		}

		private static void run_drivers_check()
        {
			Console.WriteLine("[+] Checking loaded drivers...");
			List<KeyValuePair<ulong, string>> blacklisted_drivers = get_blacklisted_drivers();
			if (blacklisted_drivers.Count > 0)
			{
				foreach (KeyValuePair<ulong, string> blacklisted_driver in blacklisted_drivers)
				{
					Console.WriteLine(String.Format("DRIVERS BLACKLIST MATCH: Loaded driver {1} matches hardcoded blacklist hash {0}", blacklisted_driver.Key, blacklisted_driver.Value));
					Console.WriteLine("OUTCOME: SUNBURST will exit!\n");
				}
			}
			Console.WriteLine("[+] Done checking loaded drivers!\n");
		}

		private static void print_message()
        {
			Console.WriteLine("SentinelLabs SUNBUST Blacklist Checker Version 1");
			Console.WriteLine("Description: This tool checks the current system for processes, services, and drivers\nthat SUNBURST attempts to identify in its blacklist, prints the match, as well as the outcome.\n");
        }

		static void Main(string[] args)
		{
			print_message();
			run_processes_check();
			run_drivers_check();
			return;
		}
	}
}
