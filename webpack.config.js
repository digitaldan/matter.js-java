const path = require('path');

module.exports = {
    entry: './src/main/ts/service/app.ts',
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/
            }
        ]
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
        fallback: { 
            assert: require.resolve("assert"),
            fs: false,
            path: require.resolve("path-browserify"),
            console: false
         }
    },
    output: {
        filename: 'bundle.js', // single output JS file
        path: path.resolve(__dirname, 'dist')
    }
};
