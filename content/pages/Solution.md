Öncelikle bu benim çözdüğüm ilk zafiyetli makinem o yüzden pekçok şeyi araştırmam gerekti.Daha önceden arkadaşlarımın 
çözdükleri makinelere bakarak  az buçuk bir şeyler kaptığımı düşünüyordum.Daha önce öğrendiklerimin faydasını yeni yeni
gördüğümü söyleyebilirim.İlk olarak makineyi ![şu linkten](https://www.vulnhub.com/entry/hackfest2016-quaoar,180/)
indirerek vmplayer sanallaştırma ortamında ayaklandırdım ve açtığımda beni şöyle bir ekran karşıladı. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/1.png)

Bu makineyi çözebilmek için üç farklı adımı gerçekleştirmek gerektiğini görebiliyordum.
İlk adım, hedef sisteme bir shell erişimi elde etmek.
İkinci adım, yetkili kullanıcı haklarına yükselmek.
Üçüncü adım ise post exploitation işlemleri ile flag'i elde etmek.
İlk adımı gerçekleştirebilmek için hedef sistemde açık olan portları ve servisleri nmap aracı ile araştırmaya başladım.Yaptığım taramanın sonucu şöyle idi, 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/2.png)

80 portunun açık olduğunu görünce tarayıcım ile bir ziyarette bulundum. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/3.png)

Web sitesi hakkında bişeyler öğrenmek için niktoyla tarama yaptım 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/4.png)

Nikto bana robots.txt dosyası bulmuştu mutlu olup içinde hangi dizinlere hangi izinlerin verildiğine baktım. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/5.png)

/wordpress dizinine gittiğimde karşıma Wordpress blogu çıktı. Aynı dizini Dirbuster gibi araçlar ile de bulabilirdik fakat burada robots.txt içeriğini okuyarak zahmet etmeden bu bilgiyi elde etmiş olduk.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/6.png)

Ardından acaba bu aşamayı nasıl geçebilirim diye düşündüm ve Kali Linuxteki araçlardan daha önce gördüğüm veya bana 
yardımcı olabilecek bir tool var mı diye biraz araştırma yapmtım ve karşıma WPScan çıktı.WPScan'ın nasıl kullanıcağını pek
bilmesemde Youtube'da biraz araştırmay ile işime yarayabilecek bir kaç komut buldum ve taradım bizim linki.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/7.png)

Buradan da ...
WPScan'den gelen sonuca göre bu siteyi kuran arkadaş öntanımlı kullanıcı adı ve parolayı değiştirmemiş.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/7.1.png)

Elde ettiğim admin/admin kullanıcı adı ve parola ikilisi ile panele(http://192.186.1.106/wordpress/wp-login[192.168.1.106 kısmı benim makinemin aldığı ip]) giriş yapabildim. Şimdi hedef sisteme shell erişimi elde etmek için neler yapabiliriz onu düşünmek kaldı. Elimde yönetici paneline yetkili kullanıcı ile erişim elde edebildiğim bir wordpress sitesi vardı ve ben de geçmiş tecrübelerime dayanarak php shell e yöneldim. Tarayıcı üzerinden erişebildiğim bir yere sistem komutları çalıştırabileceğim ya da doğrudan sisteme bağlantı elde edebileceğim zararlı bir php dosyası üretmem gerekiyordu. Bunun için de msfvenom aracını kullandım.  

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/8.png)

Ardından, wordpress panelinde tema ayarlarından son kullanıcıya gösterilen 404 hata sayfasının kodlarına küçük bir müdahalede bulunarak bir önceki aşamada msfvenom ile ürettiğim zararlı php kodunu buraya yapıştırdım. Böylelikle sitede varolmayan bir URL'e ulaşmak istediğimde Wordpress bana bu 404 sayfasını dönecekti. Yani benim zararlı kodum çalışacaktı.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/9.png)

Bu aşamada, varolmayan bir URL'e istekte bulunduğumda wordpress bana 404 hata sayfasını dönecekti. 404 hata sayfasının değiştirilmiş içeriğinde ise benim sistemime doğrudan bağlantı isteği gönderecek php kodu vardı. Yani benim önce dinlemeye geçmem lazım ki 404 hata sayfasına istek gönderdiğimde o hata sayfasındaki php kodu çalışıp bana ulaşabilsin. Bu sebeple Metasploit Framework içerisinde bulunan exploit/multi/handler modülünü msfvenom ile oluşturduğum php shell'e göre ayarladım ve dinlemeye geçtim. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/10.png)

Ziyaret ettiğim sayfa bana 404 dönmüş olsa da 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/11.png)

Handler'ım bağlantıyı yakaladı!

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/12.png)

Geriye iki adım kaldı.ilki vaktimi almıştı şimdi hedef ikincisindeydi "root olmak" bunun için web sitesine
biraz göz gezdirdim.Meterpreter erişimim üzerinden ilerlemeye karar verdim. python -c 'import pty;pty.spawn("/bin/bash")'  komutu ile etkileşimli shell'e geçerek daha rahat hareket etmeye başladım ve sistemin içinde bulunan konfigürasyon dosyalarını incelemeye başladım.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/13.png)

Bu basit bir makine dedim kendi kendime çok kapsamlı düşünmeye gerek yok ha ordadır ha burda diye düşünüp makinenin içini 2 yaşındaki misafir çocuğu edasıyla
her dosyayı açıp kapatıp oynarken karşıma birşey daha geldi 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/14.png)

-hemen ardından gelen hunharca kahkahamıda unutmadık- işte parola.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/15.png)

Bulduğum şifre ve parolayı kullanarak yalnız parolada "!" unutmadığınıza emin olarak root oluyorum.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/16.png)

Şimdi sadece flag'i bulmak  kaldı.Makinede root oluduğumda bulunduğum dizini kontrol ediyorum ve flag karşılıyor beni

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/17.png)

bu makinede böyle hüzünlü bir sonla bitiyor daha nice makinelerde görüşmek üzere ...

