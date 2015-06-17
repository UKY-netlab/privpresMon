d3.helper = {};

d3.helper.tooltip = function(accessor){
    return function(selection){
        var tooltipDiv;
        var bodyNode = d3.select('body').node();
        selection.on("mouseover", function(d, i){
            // Clean up lost tooltips
            d3.select('body').selectAll('div.tooltip').remove();
            // Append tooltip
            tooltipDiv = d3.select('body').append('div').attr('class', 'tooltip');
            var absoluteMousePos = d3.mouse(bodyNode);
            
            // Add text using the accessor function
            var tooltipText = accessor(d, i) || '';
            var lines = tooltipText.split("<br>");
            var numLines = lines.length
            var maxLineLen = 0;
            for(i=0; i<numLines; i++){
                if(lines[i].length > maxLineLen)
                    maxLineLen = lines[i].length;
            }

            tooltipDiv.style('left', (absoluteMousePos[0] - maxLineLen*3.5)+'px')
                .style('top', (absoluteMousePos[1] + 2 - numLines*20)+'px')
                .style('position', 'absolute') 
                .style('z-index', 1001)
                .html(tooltipText);
        })
        .on('mousemove', function(d, i) {
            // Move tooltip
            var absoluteMousePos = d3.mouse(bodyNode);
            
            var tooltipText = accessor(d, i) || '';
            var lines = tooltipText.split("<br>");
            var numLines = lines.length
            var maxLineLen = 0;
            for(i=0; i<numLines; i++){
                if(lines[i].length > maxLineLen)
                    maxLineLen = lines[i].length;
            }

            tooltipDiv.style('left', (absoluteMousePos[0] - maxLineLen*3.5)+'px')
                .style('top', (absoluteMousePos[1] + 2 - numLines*20)+'px')
                .html(tooltipText);
        })
        .on("mouseout", function(d, i){
            // Remove tooltip
            tooltipDiv.remove();
        });

    };
};