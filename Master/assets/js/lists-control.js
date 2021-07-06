$("#exit").click(function(){
  if (confirm("Are you sure to close EagleEye?")){
    $.get("/exit", function(data, status){});
    close();
  }
});

document.addEventListener('DOMContentLoaded', function() {
 if (!Notification) {
  alert('Desktop notifications not available in your browser. Try Chromium.');
  return;
 }

 if (Notification.permission !== 'granted')
  Notification.requestPermission();
});


function notify(text) {
 if (Notification.permission !== 'granted'){
  Notification.requestPermission();
}
  var notification = new Notification('Security Alert!', {
   icon: '/assets/img/favicon.png',
   body: text,
  });
  notification.onclick = function() {
   window.open('#threats-list');
  };
  return true;
}

var ips = [];
setInterval(function(){
  try{
      $.getJSON('/devices_list', function(data) {
      // console.log(data);
      for (var i in data) {
          if(ips.includes(data[i].device_ip)==false){
            ips.push(data[i].device_ip);
            $('#devices-list').append( "<li class='list-group-item list-group-item-action text-success'><a title='Status: "+data[i].Status+"&#013;Device name: "+data[i].Devices_name+"&#013;System user: "+data[i].User_name+"&#013;Operating system: "+data[i].OS+"'>"+ data[i].device_ip +"</a></li>");
          }
      }
    });
  } catch(e){
    console.log(e);
  }
  }
,5000);

var threats = [];
setInterval(function(){
    $.getJSON('/threats_list', function(data) {
      try {
        // console.log(data);
        for (var threat of Object.keys(data)) {
            if(threats.includes(threat)==false){
              threats.push(threat);
              if(!notify(data[threat].info.title)){
                // $('#alert-body').text(data[threat].info.title);
                // $('.alert').css('visibility', 'visible');
            }
              $('#threats-list').append( "<li class='list-group-item list-group-item-action text-danger'><a title='Source: "+data[threat].source+"&#013;Packets: "+data[threat].count+"&#013' href='"+data[threat].info.reference+"' class='not-link' target='_blank'>"+ data[threat].info.title +"</a></li>");
            }
        }
    } catch(e){
      console.log(e);
    }
    });
  }
,5000);
