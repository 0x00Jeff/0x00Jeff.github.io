
class utils {
  static getContentVisibilityHeight() {
    var docHeight = $('.visible').height(),
      winHeight = $(window).height(),
      contentVisibilityHeight = (docHeight > winHeight) ? (docHeight - winHeight) : ($(document).height() - winHeight);
    return contentVisibilityHeight;
  }

  static isMobile() {
    return window.screen.width < 767;
  }
}
