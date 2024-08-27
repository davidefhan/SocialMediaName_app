    <DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Social Media App</title>
                <script src="node_modules/angular/angular.min.js"></script>
            </head>
            <body ng-app="socialMediaApp">
                <div ng-controller="MainController">
                    <h1>{{ message }}</h1>
                </div>

                <script>
                    var app = angular.module('socialMediaApp', []);
                    app.controller('MainController', function($scope){
                        $scope.message = 'Welcome to Social Media App!';
                    });
                </script>
            </body>
        </html>