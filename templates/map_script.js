function draw_map(input) {
    function drawRegionsMap() {

      var data = google.visualization.arrayToDataTable(input);

      var options = {};

      var chart = new google.visualization.GeoChart(document.getElementById('regions_div'));

      chart.draw(data, options);
    }

    google.load("visualization", "1", {packages:["geochart"]});
    google.setOnLoadCallback(drawRegionsMap);
}