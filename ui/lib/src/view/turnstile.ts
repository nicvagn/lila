import { requestIdleCallback } from 'lib';

export default function turnstile($form: Cash): void {
  $form.find('.submit').prop('disabled', true);
  const selector = '.cf-turnstile';
  const el = $form[0]!.querySelector<HTMLDivElement>(selector)!;
  el.innerHTML = '';
  const options = Object.assign({}, el.dataset);
  const showError = (message: string | false) => {
    const $err = $(selector).find('.cf-turnstile-error');
    if (message) $err.text(message).removeClass('none');
    else $err.addClass('none');
  };
  requestIdleCallback(() => {
    window.turnstile.render(selector, {
      ...options,
      appearance: 'interaction-only',
      callback: () => {
        $form.find('.submit').prop('disabled', false);
        // showError(false);
        showError('Captcha completed, you can submit now');
      },
      'error-callback': (errorCode: string) => {
        showError('Captcha error: ' + errorCode);
      },
      'expired-callback': () => {
        showError('Captcha expired, please try again');
      },
      'timeout-callback': () => {
        showError('Captcha timed out');
      },
    });
  });
}
