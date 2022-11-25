function draw_map(data) {
    function drawRegionsMap() {

      var data = google.visualization.arrayToDataTable([
        ['Country', 'Number'],
        data
      ]);

      var options = {};

      var chart = new google.visualization.GeoChart(document.getElementById('regions_div'));

      chart.draw(data, options);
    }

    google.load("visualization", "1", {packages:["geochart"]});
    google.setOnLoadCallback(drawRegionsMap);
}