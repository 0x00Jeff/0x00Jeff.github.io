var gulp = require('gulp'),
    uglify = require('gulp-uglify'), // 压缩js文件
    sass = require('gulp-sass'), // 编译sass
    cleanCSS = require('gulp-clean-css'), // 压缩css文件
    rename = require('gulp-rename'); // 文件重命名

gulp.task('scripts', function(){
    gulp.src('_darkness/js/index.js')
        .pipe(uglify())
        .pipe(rename({suffix: '.min'}))
        .pipe(gulp.dest('assets/js'))
});

gulp.task('sass', function(){
    gulp.src('_darkness/sass/app.scss')
        .pipe(sass())
        .pipe(gulp.dest('_darkness/sass'))
        .pipe(cleanCSS())
        .pipe(rename({suffix: '.min'}))
        .pipe(gulp.dest('assets/css'));
});

gulp.task('watch', function(){
    gulp.watch('_darkness/sass/*.scss', ['sass']);
    gulp.watch('_darkness/js/*.js', ['scripts']);
});

gulp.task('default', ['scripts', 'sass', 'watch']);