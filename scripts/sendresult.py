import utils
import define

def send_output_result():
    s = utils.test_metadata()
    utils.recv_frame(s)
    
    result = utils.p32_b(define.result['CALLBACK_OUTPUT'])
    result += 'kIss My AsS'

    while raw_input('>') == 'y':
        print('Send result: ' + repr(result))
        print('\n ---------------- \n')
        enc = utils.bs_encrypt(result)

        results = utils.p32_b(len(enc)) + enc
        utils.send_frame(s, results)
        utils.recv_frame(s)

if __name__ == '__main__':
    send_output_result()