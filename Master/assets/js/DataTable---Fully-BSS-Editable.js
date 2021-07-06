function format ( d ) {
    let details = "<ul>"
    details += '<li><strong>Device IP:</strong> '+d.ip+'</li>'
    details += '<li><strong>Packet received at:</strong> '+d.time+'</li>'
    if (d.dns_query != null)
      details +='<li><strong>DNS query:</strong> '+d.dns_query+'</li>'

    details +="</ul>"
    if (d.srcmac != null && d.srcmac !='-'){
      details += '<details><summary>Ethernet</summary><ul>'
      details += '<li><strong>Source MAC:</strong> '+d.srcmac+'</li>'
      details += '<li><strong>Destination MAC:</strong> '+d.dstmac+'</li>'
      details += '<li><strong>Type:</strong> '+d.ethernet_type+'</li></ul>'
      details += '</details>'
    }
    if (d.srcip != null && d.srcip !='-'){
      details += '<details><summary>IPv4</summary><ul>'
      details += '<li><strong>Source IP:</strong> '+d.srcip+'</li>'
      details += '<li><strong>Destination IP:</strong> '+d.dstip+'</li>'
      details += '<li><strong>Protocol:</strong> '+d.ip_proto+'</li>'
      details += '</ul></details>'
    }
    if (d.tcp_srcport != null){
      details += '<details><summary>TCP</summary><ul>'
      details += '<li><strong>Source port:</strong> '+d.tcp_srcport+'</li>'
      details += '<li><strong>Destination port:</strong> '+d.tcp_dstport+'</li>'
      details += '<li><strong>Sequence:</strong> '+d.tcp_seq+'</li>'
      details += '</ul></details>'
    }
    if (d.udp_srcport != null){
      details += '<details><summary>UDP</summary><ul>'
      details += '<li><strong>Source port:</strong> '+d.udp_srcport+'</li>'
      details += '<li><strong>Destination port:</strong> '+d.udp_dstport+'</li>'
      details += '<li><strong>Length:</strong> '+d.udp_length+'</li>'
      details += '</ul></details>'
    }
    if (d.ICMPType != null){
      details += '<details><summary>ICMPv4</summary><ul>'
      details += '<li><strong>Type:</strong> '+d.ICMPType+'</li>'
      details += '<li><strong>Sequence:</strong> '+d.ICMPSeq+'</li>'
      details += '<li><strong>Checksum:</strong> '+d.ICMPChecksum+'</li>'
      details += '</ul></details>'
    }
    if (d.payload != null){
      details += '<details><summary><strong>Application layer payload</strong></summary>'
      details += '<p>'+d.payload+'</p>';
      details += '</details>'
    }
    return details;
}

$(document).ready(function() {
    var table = $('.mydatatable').DataTable({
        dom: 'Bfrti<p>',
        ajax:"/results_table",
        "columns": [
            {
                "className":      'details-control',
                "orderable":      false,
                "data":           null,
                "defaultContent": '',
                "render": function () {
                         return '<i class="fa fa-plus-square" aria-hidden="true"></i>';
                     },
                width:"15px"
            },
            { "data": "ip" },
            { "data": "time" },
            { "data": "protocols" },
            { "data": "app_layer" },
            { "data": "srcmac" },
            { "data": "dstmac" },
            { "data": "srcip" },
            { "data": "dstip" }
        ],
        columnDefs: [
          {
              targets: 4,
              className: 'text-center'
          }
        ],
        buttons: [
            {
                extend: 'collection',
                text: 'Export data as',
                buttons: [ 'csv', 'excel', 'pdf' ]
            },
            'copy', 'print'
        ],
        responsive: true,
        scrollY: 400,
        scrollX: true,
        autoWidth: true,
        scrollCollapse: true,
        paging: true,
        info: false,
        ordering: false,
        pagingType: "simple_numbers"
    });
    setInterval( function () { table.ajax.reload(); }, 60000 );
    $('.mydatatable tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var tdi = tr.find("i.fa");
        var row = table.row( tr );

        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
            tdi.first().removeClass('fa-minus-square');
            tdi.first().addClass('fa-plus-square');
        }
        else {
            // Open this row
            row.child( format(row.data()) ).show();
            tr.addClass('shown');
            tdi.first().removeClass('fa-plus-square');
            tdi.first().addClass('fa-minus-square');
        }
    } );
});
