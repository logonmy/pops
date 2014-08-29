var update_view_interval_id;

function getParameterByName(name, url) {
  name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
  var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
    results = regex.exec(url || location.search);
  return results == null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function update_view() {
  var host_port = $('#host_port').val();
  var url = 'http://' + host_port + '/stat/';
  $.ajax({
           url: url,
           beforeSend: function (xhr) {
             var username = $('#username').val();
             var password = $('#password').val();
             var auth_in_base64 = btoa(username + ':' + password);

             if (username && password) {
               xhr.headers = {
                 Authorization: 'Basic ' + auth_in_base64,
               };
             }
           }
         })
    .success(function (data) {
               var info = data['server_info'];
               $('#serving_on').text(info['serving_on']);
               $('#service_mode').text(info['service_mode']);
               $('#pid').text(info['pid']);
               $('#error_log').text(info['error_log']);
               $('#processes').text(info['processes']);
               $('#cpu_count').text(info['cpu_count']);

               var stat;
               if (info['service_mode'] === 'slot') {

                 var tag_node_list = $('#node_list');
                 tag_node_list.empty();

                 var parser = document.createElement('a');
                 parser.href = document.URL;

                 var node_list = data['node_list'];

                 for (var i = 0; i < node_list.length; i++) {
                   var item = node_list[i];
                   var status = parseInt(item['_status']);
                   var host_port = item['_host_port'];

                   var node_href = '?host_port=' + host_port +
                     '&username=' + $('#username').val() +
                     '&password=' + $('#password').val();
                   var s = '<a href="' + node_href + '" class="list-group-item" target="_blank">' + host_port + '</a>';
                   s = (status === 1) ? $(s).css('color', 'green') : $(s).css('color', 'red');
                   tag_node_list.append(s);
                 }

                 stat = data['stat_slot'];
               } else {
                 stat = data['stat_node'];
               }
               $('#requests').text(stat['requests']);
               $('#processing').text(stat['processing']);
               $('#proxy_requests').text(stat['proxy_requests']);

               if (!update_view_interval_id) {
                 update_view_interval_id = window.setInterval(update_view, 1000);
               }

             })
    .error(function (xhr, textStatus, err) {

             var msg = '<div class="alert alert-warning alert-dismissible container-fluid" role="alert" id="alert">' +
               '<button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>' +
               '<strong>Error!</strong> get info failed' +
               '</div>';
             $(msg).insertBefore($('h1'));

             $("#alert").fadeTo(1000, 250).slideUp(200, function () {
               $("#alert").alert('close');

               $("#btn_connect").removeAttr("disabled");
             });

             if (update_view_interval_id) {
               clearInterval(update_view_interval_id);
             }

             console.log(err);
           });
}

function update_settings() {
  var node_kick_slow_than = $('#node_kick_slow_than').val();
  var node_per_domain_max_concurrency = $('#node_per_domain_max_concurrency').val();
  var node_check_interval = $('#node_check_interval').val();
  var node_test_max_concurrency = $('#node_test_max_concurrency').val();

}

function update_slot_node_info_from_url() {
  var host_port = getParameterByName('host_port', document.URL);
  if (host_port) {
    $('#host_port').val(host_port);
  }

  var username = getParameterByName('username', document.URL);
  if (username) {
    $('#username').val(username);
  }

  var password = getParameterByName('password', document.URL);
  if (password) {
    $('#password').val(password);
  }
}

$(document).ready(function () {
  update_slot_node_info_from_url();

  $("#btn_connect").click(function (event) {
    event.preventDefault();
    update_view();
  });

  $('#btn_update').click(function (event) {
    event.preventDefault();
    update_settings();
  });

  var parser = document.createElement('a');
  parser.href = document.URL;
  if (parser.search) {
    var btn = $("#btn_connect");
    btn.click();
    btn.prop("disabled", true);
  }

});