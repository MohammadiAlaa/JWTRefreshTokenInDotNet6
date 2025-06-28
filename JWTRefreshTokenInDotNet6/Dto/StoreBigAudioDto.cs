namespace VoiceDetection.Dto
{
    public class StoreBigAudioDto
    {
        public IFormFile BigAudio { get; set; }
        public string Result { get; set; }
        public float Confidence { get; set; }
    }

}
